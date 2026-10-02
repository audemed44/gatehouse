package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/audemed44/gatehouse/internal/config"
)

// table is one compiled config. Requests read it through an atomic
// pointer, so a reload swaps it whole and in-flight requests finish on the
// table they started with.
type table struct {
	exact    map[string]*route
	wildcard map[string]*route // "*.example.com" stored as "example.com"
	cfg      config.Config
}

type route struct {
	host     *config.Host
	redirect *config.Redirect
	target   *url.URL
	proxy    *httputil.ReverseProxy
	allow    []netip.Prefix
	users    map[string]string // user → bcrypt hash
	authOK   sync.Map          // sha256(user:password) → true, so bcrypt runs once per login
	maxBody  int64
}

func (rt *table) lookup(host string) *route {
	if r, ok := rt.exact[host]; ok {
		return r
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		if r, ok := rt.wildcard[host[i+1:]]; ok {
			return r
		}
	}
	return nil
}

func (rt *table) add(domains []string, r *route) {
	for _, d := range domains {
		if rest, ok := strings.CutPrefix(d, "*."); ok {
			rt.wildcard[rest] = r
		} else {
			rt.exact[d] = r
		}
	}
}

// transports are shared by upstream settings and survive reloads, so
// keep-alive connections to upstreams aren't dropped by a config change.
type transports struct {
	mu  sync.Mutex
	all map[string]*http.Transport
}

func (t *transports) get(insecure bool, timeout time.Duration) *http.Transport {
	key := fmt.Sprintf("%v/%s", insecure, timeout)
	t.mu.Lock()
	defer t.mu.Unlock()
	if tr, ok := t.all[key]; ok {
		return tr
	}
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // per-host opt-in for self-signed upstreams
	}
	t.all[key] = tr
	return tr
}

// errorLog drops the "context canceled" noise from clients going away.
var errorLog = log.New(logWriter{}, "", 0)

type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if !strings.Contains(msg, "context canceled") {
		slog.Debug("proxy", "msg", msg)
	}
	return len(p), nil
}

// compile turns a validated config into a routing table.
func (p *Proxy) compile(c config.Config) (*table, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	rt := &table{exact: map[string]*route{}, wildcard: map[string]*route{}, cfg: c}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if !h.Enabled {
			continue
		}
		target, _ := config.ParseUpstream(h.Upstream)
		var timeout time.Duration
		if h.Timeout != "" {
			timeout, _ = time.ParseDuration(h.Timeout)
		}
		r := &route{host: h, target: target, maxBody: int64(h.MaxBodyMB) << 20}
		for _, a := range h.Allow {
			pfx, _ := config.ParsePrefix(a)
			r.allow = append(r.allow, pfx)
		}
		if len(h.BasicAuth) > 0 {
			r.users = map[string]string{}
			for _, u := range h.BasicAuth {
				r.users[u.User] = u.Hash
			}
		}
		r.proxy = p.reverseProxy(r, p.transports.get(h.InsecureUpstream, timeout))
		rt.add(h.Domains, r)
	}
	for i := range c.Redirects {
		rd := &c.Redirects[i]
		if !rd.Enabled {
			continue
		}
		target, _ := config.RedirectTarget(rd.Target)
		rt.add(rd.Domains, &route{redirect: rd, target: target})
	}
	return rt, nil
}

func (p *Proxy) reverseProxy(r *route, tr *http.Transport) *httputil.ReverseProxy {
	h := r.host
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(r.target)
			// Keep the Host the browser asked for, as Nginx Proxy Manager
			// does: apps build links and check origins against it.
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			if ip := clientIP(pr.In); ip.IsValid() {
				pr.Out.Header.Set("X-Real-IP", ip.String())
			}
			for k, v := range h.RequestHeaders {
				pr.Out.Header.Set(k, v)
			}
		},
		Transport:     tr,
		FlushInterval: -1, // stream as it comes: event streams, live logs
		ErrorLog:      errorLog,
		ModifyResponse: func(resp *http.Response) error {
			for k, v := range h.ResponseHeaders {
				resp.Header.Set(k, v)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			p.upstreamError(w, req, r, err)
		},
	}
}

func authKey(user, pass string) [32]byte {
	return sha256.Sum256([]byte(user + "\x00" + pass))
}
