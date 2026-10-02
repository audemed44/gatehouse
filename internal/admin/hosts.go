package admin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/proxy"
	"github.com/audemed44/gatehouse/internal/sleep"
)

// certRef is the certificate a domain is served with.
type certRef struct {
	Name     string    `json:"name"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
}

type hostView struct {
	config.Host
	Certificate *certRef         `json:"certificate"`
	Uncovered   []string         `json:"uncovered"` // domains with no certificate
	Sleep       *sleep.Status    `json:"sleep"`
	Stats       *proxy.HostStats `json:"stats"`
}

func (s *Server) certFor(domain string) *certRef {
	if strings.HasPrefix(domain, "*.") {
		domain = "x" + domain[1:] // any name the wildcard covers
	}
	_, c := s.Certs.For(domain)
	if c == nil {
		return nil
	}
	return &certRef{Name: c.Name, NotAfter: c.NotAfter, DaysLeft: c.DaysLeft(time.Now())}
}

func (s *Server) hostViews() []hostView {
	cfg := s.Proxy.Config()
	stats := map[string]proxy.HostStats{}
	for _, st := range s.Proxy.Log.Stats() {
		stats[st.Host] = st
	}
	out := make([]hostView, 0, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		v := hostView{Host: h, Uncovered: []string{}}
		v.BasicAuth = redactUsers(h.BasicAuth)
		for _, d := range h.Domains {
			ref := s.certFor(d)
			if ref == nil {
				v.Uncovered = append(v.Uncovered, d)
			} else if v.Certificate == nil || ref.NotAfter.Before(v.Certificate.NotAfter) {
				v.Certificate = ref
			}
			if st, ok := stats[d]; ok {
				if v.Stats == nil {
					v.Stats = &proxy.HostStats{Host: h.Domains[0]}
				}
				v.Stats.Requests += st.Requests
				v.Stats.Status2 += st.Status2
				v.Stats.Status3 += st.Status3
				v.Stats.Status4 += st.Status4
				v.Stats.Status5 += st.Status5
				v.Stats.Bytes += st.Bytes
				if st.LastSeen.After(v.Stats.LastSeen) {
					v.Stats.LastSeen = st.LastSeen
				}
			}
		}
		if h.IdleStop != "" && s.Sleep != nil {
			if st, ok := s.Sleep.Status(h.Container); ok {
				v.Sleep = &st
			}
		}
		out = append(out, v)
	}
	return out
}

// redactUsers drops password hashes from API answers.
func redactUsers(in []config.BasicUser) []config.BasicUser {
	out := make([]config.BasicUser, len(in))
	for i, u := range in {
		out[i] = config.BasicUser{User: u.User}
	}
	return out
}

func (s *Server) listHosts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.hostViews())
}

// uniqueID makes id unique among taken by adding -2, -3, ….
func uniqueID(id string, taken func(string) bool) string {
	if !taken(id) {
		return id
	}
	for n := 2; ; n++ {
		if c := id + "-" + strconv.Itoa(n); !taken(c) {
			return c
		}
	}
}

func (s *Server) saveHost(w http.ResponseWriter, r *http.Request) {
	var h config.Host
	if !readJSON(w, r, 64<<10, &h) {
		return
	}
	id := r.PathValue("id")
	var saved config.Host
	_, err := s.update(func(c *config.Config) error {
		idx := -1
		if id != "" {
			idx = slices.IndexFunc(c.Hosts, func(x config.Host) bool { return x.ID == id })
			if idx < 0 {
				return errNotFound
			}
		}
		// Passwords: hash new ones, keep the hash of users sent without one.
		var old []config.BasicUser
		if idx >= 0 {
			old = c.Hosts[idx].BasicAuth
		}
		for i, u := range h.BasicAuth {
			u.User = strings.TrimSpace(u.User)
			u.Hash = ""
			if u.Password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
				if err != nil {
					return invalid{err}
				}
				u.Hash, u.Password = string(hash), ""
			} else if j := slices.IndexFunc(old, func(o config.BasicUser) bool { return o.User == u.User }); j >= 0 {
				u.Hash = old[j].Hash
			}
			h.BasicAuth[i] = u
		}
		if idx >= 0 {
			h.ID = id
			c.Hosts[idx] = h
		} else {
			tmp := config.Config{Hosts: []config.Host{h}}
			tmp.Normalize()
			h.ID = uniqueID(tmp.Hosts[0].ID, func(x string) bool { return idTaken(c, x) })
			c.Hosts = append(c.Hosts, h)
		}
		saved = h
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	for _, v := range s.hostViews() {
		if v.ID == saved.ID {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	writeJSON(w, http.StatusOK, saved)
}

func idTaken(c *config.Config, id string) bool {
	for _, h := range c.Hosts {
		if h.ID == id {
			return true
		}
	}
	for _, r := range c.Redirects {
		if r.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, err := s.update(func(c *config.Config) error {
		n := len(c.Hosts)
		c.Hosts = slices.DeleteFunc(c.Hosts, func(h config.Host) bool { return h.ID == id })
		if len(c.Hosts) == n {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type testResult struct {
	Upstream struct {
		OK      bool   `json:"ok"`
		Status  int    `json:"status,omitempty"`
		Millis  int64  `json:"ms"`
		Message string `json:"message"`
	} `json:"upstream"`
	DNS []dnsResult `json:"dns"`
}

type dnsResult struct {
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
	Cert      *certRef `json:"certificate"`
}

// testHost checks a host before saving: does the upstream answer, do the
// domains resolve, and is there a certificate for them.
func (s *Server) testHost(w http.ResponseWriter, r *http.Request) {
	var h config.Host
	if !readJSON(w, r, 64<<10, &h) {
		return
	}
	tmp := config.Config{Hosts: []config.Host{h}}
	tmp.Normalize()
	h = tmp.Hosts[0]
	var res testResult
	res.DNS = []dnsResult{}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	if u, err := config.ParseUpstream(h.Upstream); err != nil {
		res.Upstream.Message = err.Error()
	} else {
		client := &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: h.InsecureUpstream}, //nolint:gosec // mirrors the host's setting
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+"/", nil)
		if len(h.Domains) > 0 && !strings.HasPrefix(h.Domains[0], "*.") {
			req.Host = h.Domains[0]
		}
		resp, err := client.Do(req)
		res.Upstream.Millis = time.Since(start).Milliseconds()
		if err != nil {
			res.Upstream.Message = upstreamMessage(err, h)
		} else {
			resp.Body.Close()
			res.Upstream.OK = true
			res.Upstream.Status = resp.StatusCode
			res.Upstream.Message = fmt.Sprintf("answered HTTP %d in %d ms", resp.StatusCode, res.Upstream.Millis)
		}
	}
	for _, d := range h.Domains {
		dr := dnsResult{Domain: d, Addresses: []string{}, Cert: s.certFor(d)}
		name := d
		if strings.HasPrefix(d, "*.") {
			name = "gatehouse-check" + d[1:]
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			dr.Error = "doesn't resolve"
		} else {
			dr.Addresses = addrs
		}
		res.DNS = append(res.DNS, dr)
	}
	writeJSON(w, http.StatusOK, res)
}

func upstreamMessage(err error, h config.Host) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return "the upstream's name doesn't resolve: is the container on the same Docker network?"
	case strings.Contains(msg, "connection refused"):
		if h.IdleStop != "" {
			return "connection refused: it may be asleep"
		}
		return "connection refused: nothing is listening on that port"
	case strings.Contains(msg, "certificate"):
		return "its HTTPS certificate isn't trusted; tick “Don't verify the upstream's certificate” for self-signed ones"
	case strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "deadline"):
		return "no answer within 6 seconds"
	}
	return msg
}

func (s *Server) hostByID(id string) (config.Host, bool) {
	for _, h := range s.Proxy.Config().Hosts {
		if h.ID == id {
			return h, true
		}
	}
	return config.Host{}, false
}

func (s *Server) wakeHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostByID(r.PathValue("id"))
	if !ok || s.Sleep == nil {
		fail(w, errNotFound)
		return
	}
	if err := s.Sleep.Wake(h.Container); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) sleepHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostByID(r.PathValue("id"))
	if !ok || s.Sleep == nil {
		fail(w, errNotFound)
		return
	}
	if err := s.Sleep.Sleep(r.Context(), h.Container); err != nil {
		writeError(w, http.StatusConflict, "can't put it to sleep: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type redirectView struct {
	config.Redirect
	Certificate *certRef `json:"certificate"`
}

func (s *Server) listRedirects(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Proxy.Config()
	out := make([]redirectView, 0, len(cfg.Redirects))
	for _, rd := range cfg.Redirects {
		v := redirectView{Redirect: rd}
		if len(rd.Domains) > 0 {
			v.Certificate = s.certFor(rd.Domains[0])
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) saveRedirect(w http.ResponseWriter, r *http.Request) {
	var rd config.Redirect
	if !readJSON(w, r, 16<<10, &rd) {
		return
	}
	id := r.PathValue("id")
	_, err := s.update(func(c *config.Config) error {
		if id != "" {
			idx := slices.IndexFunc(c.Redirects, func(x config.Redirect) bool { return x.ID == id })
			if idx < 0 {
				return errNotFound
			}
			rd.ID = id
			c.Redirects[idx] = rd
			return nil
		}
		tmp := config.Config{Redirects: []config.Redirect{rd}}
		tmp.Normalize()
		rd.ID = uniqueID(tmp.Redirects[0].ID, func(x string) bool { return idTaken(c, x) })
		c.Redirects = append(c.Redirects, rd)
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	for _, x := range s.Proxy.Config().Redirects {
		if x.ID == rd.ID {
			rd = x
		}
	}
	writeJSON(w, http.StatusOK, rd)
}

func (s *Server) deleteRedirect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, err := s.update(func(c *config.Config) error {
		n := len(c.Redirects)
		c.Redirects = slices.DeleteFunc(c.Redirects, func(x config.Redirect) bool { return x.ID == id })
		if len(c.Redirects) == n {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
