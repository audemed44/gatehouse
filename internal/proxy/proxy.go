// Package proxy is Gatehouse's front door: it routes requests by host name
// to upstreams or redirects, with per-host HTTPS, HSTS, headers, IP
// allowlists, basic auth, body limits and scale-to-zero.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/sleep"
)

type Proxy struct {
	Certs  *certs.Store
	Log    *AccessLog
	Sleep  *sleep.Manager
	tables atomic.Pointer[table]

	transports transports
}

func New(store *certs.Store, sleeper *sleep.Manager, logSize int) *Proxy {
	p := &Proxy{Certs: store, Log: NewAccessLog(logSize), Sleep: sleeper}
	p.transports.all = map[string]*http.Transport{}
	p.tables.Store(&table{exact: map[string]*route{}, wildcard: map[string]*route{}, cfg: config.Default()})
	return p
}

// Apply validates and compiles a config and swaps it in. On error nothing
// changes: the old config keeps serving.
func (p *Proxy) Apply(c config.Config) error {
	rt, err := p.compile(c)
	if err != nil {
		return err
	}
	p.tables.Store(rt)
	p.Log.Resize(c.Settings.AccessLogSize)
	if p.Sleep != nil {
		p.Sleep.Configure(c.Hosts)
	}
	return nil
}

// Check compiles a config without applying it.
func (p *Proxy) Check(c config.Config) error {
	_, err := p.compile(c)
	return err
}

// Config is the config being served.
func (p *Proxy) Config() config.Config { return p.tables.Load().cfg }

func hostOnly(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w}
	host := hostOnly(r.Host)
	rt := p.tables.Load()
	route := rt.lookup(host)
	p.serve(rec, r, host, route)
	if route != nil || host != "" {
		p.Log.Add(Entry{
			Time: start, Host: host, Method: r.Method, Path: logPath(r.URL),
			Status: rec.code(), Bytes: rec.bytes, Millis: time.Since(start).Milliseconds(),
			Client: clientIP(r).String(), TLS: r.TLS != nil, Matched: route != nil,
		})
	}
}

// logPath drops the query: it can hold tokens.
func logPath(u *url.URL) string {
	p := u.EscapedPath()
	if len(p) > 200 {
		p = p[:200] + "…"
	}
	return p
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, host string, rt *route) {
	if rt == nil {
		page(w, http.StatusNotFound, "Nothing here", "No service is set up for "+host+".")
		return
	}
	secure := r.TLS != nil
	hasCert := false
	if !secure {
		c, _ := p.Certs.For(host)
		hasCert = c != nil
	}

	if rd := rt.redirect; rd != nil {
		if !secure && rd.ForceHTTPS && hasCert {
			toHTTPS(w, r, host)
			return
		}
		u := *rt.target
		if rd.PreservePath {
			u.Path = strings.TrimSuffix(u.Path, "/") + r.URL.Path
			u.RawPath = ""
			u.RawQuery = r.URL.RawQuery
		}
		http.Redirect(w, r, u.String(), rd.Code)
		return
	}

	h := rt.host
	if !secure && h.ForceHTTPS && hasCert {
		toHTTPS(w, r, host)
		return
	}
	if len(rt.allow) > 0 {
		ip := clientIP(r)
		allowed := false
		for _, pfx := range rt.allow {
			if pfx.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			page(w, http.StatusForbidden, "Not allowed", "This service isn't open to your address.")
			return
		}
	}
	if rt.users != nil && !rt.checkAuth(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+host+`", charset="UTF-8"`)
		page(w, http.StatusUnauthorized, "Sign in", "This service needs a user name and password.")
		return
	}
	if rt.users != nil {
		// The upstream doesn't need the proxy's password.
		r.Header.Del("Authorization")
	}
	if secure && h.HSTS {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
	}
	if rt.maxBody > 0 {
		if r.ContentLength > rt.maxBody {
			page(w, http.StatusRequestEntityTooLarge, "Too large", "The upload is bigger than this service accepts.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, rt.maxBody)
	}

	if app := p.app(h); app != nil {
		app.Begin()
		defer app.End()
		if ok, attempt := p.Sleep.Ready(app); !ok {
			if !p.waitAwake(w, r, attempt) {
				return
			}
		}
	}
	rt.proxy.ServeHTTP(w, r)
}

func (p *Proxy) app(h *config.Host) *sleep.App {
	if p.Sleep == nil || h.IdleStop == "" {
		return nil
	}
	return p.Sleep.Get(h.Container)
}

// waitAwake handles a request for a sleeping container: a browser gets a
// "waking up" page that reloads itself; anything else waits for it.
func (p *Proxy) waitAwake(w http.ResponseWriter, r *http.Request, at *sleep.Attempt) bool {
	if wantsHTML(r) {
		wakingPage(w)
		return false
	}
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	select {
	case <-at.Done:
		if at.Err != nil {
			w.Header().Set("Retry-After", "30")
			page(w, http.StatusServiceUnavailable, "Couldn't start", "The service didn't wake up: "+at.Err.Error())
			return false
		}
		return true
	case <-t.C:
	case <-r.Context().Done():
		return false
	}
	w.Header().Set("Retry-After", "5")
	page(w, http.StatusServiceUnavailable, "Waking up", "The service is still starting. Try again in a few seconds.")
	return false
}

func wantsHTML(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") &&
		r.Header.Get("Upgrade") == ""
}

func toHTTPS(w http.ResponseWriter, r *http.Request, host string) {
	u := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	code := http.StatusMovedPermanently
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		code = http.StatusPermanentRedirect // keep the method and body
	}
	http.Redirect(w, r, u.String(), code)
}

func (rt *route) checkAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, ok := rt.users[user]
	if !ok {
		return false
	}
	key := authKey(user, pass)
	if _, ok := rt.authOK.Load(key); ok {
		return true
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		return false
	}
	rt.authOK.Store(key, true)
	return true
}

// upstreamError answers when the upstream couldn't be reached. For a host
// under idle stop whose container turns out to be stopped, that's sleep,
// not an outage: a browser gets the waking page.
func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, rt *route, err error) {
	if errors.Is(err, context.Canceled) {
		w.WriteHeader(499) // the client went away; nobody sees this
		return
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		page(w, http.StatusRequestEntityTooLarge, "Too large", "The upload is bigger than this service accepts.")
		return
	}
	if app := p.app(rt.host); app != nil && isDialError(err) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		down := p.Sleep.Down(ctx, app)
		cancel()
		if down {
			p.Sleep.Ready(app) // start waking it
			if wantsHTML(r) {
				wakingPage(w)
				return
			}
			w.Header().Set("Retry-After", "5")
			page(w, http.StatusServiceUnavailable, "Waking up", "The service was asleep and is starting. Try again in a few seconds.")
			return
		}
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		page(w, http.StatusGatewayTimeout, "Timed out", "The service took too long to answer.")
		return
	}
	page(w, http.StatusBadGateway, "Can't reach the service", "The service behind "+hostOnly(r.Host)+" isn't answering. It may be stopped or restarting.")
}

func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// recorder notes the status and size for the access log. It passes
// Flush and Hijack through (via Unwrap) for streams and WebSockets.
type recorder struct {
	http.ResponseWriter
	status   int
	bytes    int64
	hijacked bool
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && code >= 200 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *recorder) Flush() {
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	return http.NewResponseController(r.ResponseWriter).Hijack()
}

func (r *recorder) code() int {
	switch {
	case r.hijacked:
		return http.StatusSwitchingProtocols
	case r.status == 0:
		return http.StatusOK
	}
	return r.status
}
