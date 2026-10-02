package admin

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/npm"
	"github.com/audemed44/gatehouse/internal/proxy"
	"github.com/audemed44/gatehouse/internal/sleep"
)

type overview struct {
	Hosts        int               `json:"hosts"`
	Enabled      int               `json:"enabled"`
	Redirects    int               `json:"redirects"`
	Certificates []certView        `json:"certificates"`
	Sleep        []sleep.Status    `json:"sleep"`
	Stats        []proxy.HostStats `json:"stats"`
	Errors       []proxy.Entry     `json:"recent_errors"`
	DockerReady  bool              `json:"docker"`
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Proxy.Config()
	o := overview{Hosts: len(cfg.Hosts), Redirects: len(cfg.Redirects), Certificates: s.certViews(),
		Stats: s.Proxy.Log.Stats(), Errors: s.Proxy.Log.Query("", true, 8), Sleep: []sleep.Status{}}
	for _, h := range cfg.Hosts {
		if h.Enabled {
			o.Enabled++
		}
	}
	if s.Sleep != nil {
		o.Sleep = s.Sleep.Statuses()
		o.DockerReady = s.Sleep.Enabled()
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": s.Proxy.Log.Query(q.Get("host"), q.Get("errors") == "1", limit),
		"stats":   s.Proxy.Log.Stats(),
	})
}

type settingsView struct {
	config.Settings
	// What the environment provides; set there, not here.
	DNSTokenSet       bool     `json:"dns_token_set"`
	Providers         []string `json:"providers"`
	NPMDir            string   `json:"npm_dir"`
	DiscoveryTokenSet bool     `json:"discovery_token_set"`
	Docker            bool     `json:"docker"`
}

func (s *Server) settingsView() settingsView {
	v := settingsView{
		Settings:          s.Proxy.Config().Settings,
		DNSTokenSet:       os.Getenv("CF_DNS_API_TOKEN") != "" || os.Getenv("CLOUDFLARE_DNS_API_TOKEN") != "",
		Providers:         certs.Providers,
		DiscoveryTokenSet: s.DiscoveryToken != "",
		Docker:            s.Sleep != nil && s.Sleep.Enabled(),
	}
	if s.NPMDir != "" {
		if _, err := os.Stat(s.NPMDir); err == nil {
			v.NPMDir = s.NPMDir
		}
	}
	return v
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsView())
}

// putSettings saves everything but the certificate list, which the
// certificate endpoints manage.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var body config.Settings
	if !readJSON(w, r, 64<<10, &body) {
		return
	}
	_, err := s.update(func(c *config.Config) error {
		body.Certificates = c.Settings.Certificates
		c.Settings = body
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView())
}

func (s *Server) readNPM(w http.ResponseWriter, r *http.Request) (*npm.Found, bool) {
	if s.NPMDir == "" {
		writeError(w, http.StatusConflict, "mount Nginx Proxy Manager's folder read-only and set GATEHOUSE_NPM_DIR")
		return nil, false
	}
	found, err := npm.Read(r.Context(), s.NPMDir)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return nil, false
	}
	return found, true
}

// previewNPM shows what an import would bring in, with the domains
// Gatehouse already serves (those are skipped).
func (s *Server) previewNPM(w http.ResponseWriter, r *http.Request) {
	found, ok := s.readNPM(w, r)
	if !ok {
		return
	}
	cfg := s.Proxy.Config()
	existing := []string{}
	for _, h := range cfg.Hosts {
		existing = append(existing, h.Domains...)
	}
	for _, rd := range cfg.Redirects {
		existing = append(existing, rd.Domains...)
	}
	held := []string{}
	for _, c := range s.Certs.List() {
		held = append(held, c.Name)
	}
	writeJSON(w, http.StatusOK, struct {
		*npm.Found
		Existing []string `json:"existing"`
		Held     []string `json:"held_certificates"`
	}{found, existing, held})
}

func (s *Server) importNPM(w http.ResponseWriter, r *http.Request) {
	found, ok := s.readNPM(w, r)
	if !ok {
		return
	}
	var rep npm.Report
	var applyErr error
	_, err := s.update(func(c *config.Config) error {
		rep, applyErr = found.Apply(c, s.Certs)
		if applyErr != nil && rep.Hosts+rep.Redirects == 0 && rep.Certs == 0 {
			return invalid{applyErr}
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	if applyErr != nil {
		rep.Warnings = append(rep.Warnings, applyErr.Error())
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) exportConfig(w http.ResponseWriter, _ *http.Request) {
	raw, err := config.ExportYAML(s.Proxy.Config())
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="gatehouse.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// importConfig replaces the whole config with an exported YAML one.
func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next, err := config.ParseYAML(raw)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	cfg, err := s.update(func(c *config.Config) error {
		*c = next
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"hosts": len(cfg.Hosts), "redirects": len(cfg.Redirects)})
}

// Discovery is the read-only view for Foyer (topology, service discovery)
// and Lookout (checks per domain, certificate expiry).
type Discovery struct {
	Hosts        []discoveryHost  `json:"hosts"`
	Redirects    []discoveryRedir `json:"redirects"`
	Certificates []discoveryCert  `json:"certificates"`
	WarnDays     int              `json:"warn_days"`
	Generated    time.Time        `json:"generated"`
}

type discoveryHost struct {
	ID          string     `json:"id"`
	Domains     []string   `json:"domains"`
	Upstream    string     `json:"upstream"`
	Scheme      string     `json:"scheme"`
	ForwardHost string     `json:"forward_host"`
	ForwardPort int        `json:"forward_port"`
	Enabled     bool       `json:"enabled"`
	HTTPS       bool       `json:"https"` // a certificate covers its domains
	Certificate string     `json:"certificate,omitempty"`
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	// Scale-to-zero: "sleeping" means stopped on purpose, not down.
	Container string `json:"container,omitempty"`
	IdleStop  string `json:"idle_stop,omitempty"`
	State     string `json:"state"` // awake, sleeping, waking, stopping
}

type discoveryRedir struct {
	ID      string   `json:"id"`
	Domains []string `json:"domains"`
	Target  string   `json:"target"`
	Code    int      `json:"code"`
	Enabled bool     `json:"enabled"`
}

type discoveryCert struct {
	Name      string    `json:"name"`
	Domains   []string  `json:"domains"`
	Issuer    string    `json:"issuer"`
	Source    string    `json:"source"`
	Expires   time.Time `json:"expires"`
	Days      int       `json:"days"`
	Hosts     int       `json:"hosts"`
	Managed   bool      `json:"managed"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Proxy.Config()
	d := Discovery{Hosts: []discoveryHost{}, Redirects: []discoveryRedir{}, Certificates: []discoveryCert{},
		WarnDays: cfg.Settings.WarnDays, Generated: time.Now().UTC()}
	for _, v := range s.hostViews() {
		h := discoveryHost{ID: v.ID, Domains: v.Domains, Upstream: v.Upstream, Enabled: v.Enabled,
			Container: v.Container, IdleStop: v.IdleStop, State: sleep.Awake}
		if u, err := config.ParseUpstream(v.Upstream); err == nil {
			h.Scheme, h.ForwardHost = u.Scheme, u.Hostname()
			h.ForwardPort, _ = strconv.Atoi(u.Port())
			if h.ForwardPort == 0 {
				h.ForwardPort = map[string]int{"http": 80, "https": 443}[u.Scheme]
			}
		}
		if v.Certificate != nil {
			h.HTTPS = len(v.Uncovered) == 0
			h.Certificate = v.Certificate.Name
			exp := v.Certificate.NotAfter
			h.CertExpires = &exp
		}
		if v.Sleep != nil {
			h.State = v.Sleep.State
		}
		d.Hosts = append(d.Hosts, h)
	}
	for _, r := range cfg.Redirects {
		d.Redirects = append(d.Redirects, discoveryRedir{ID: r.ID, Domains: r.Domains, Target: r.Target, Code: r.Code, Enabled: r.Enabled})
	}
	for _, c := range s.certViews() {
		if c.Missing {
			continue
		}
		d.Certificates = append(d.Certificates, discoveryCert{Name: c.Name, Domains: c.Domains, Issuer: c.Issuer,
			Source: c.Source, Expires: c.NotAfter, Days: c.DaysLeft, Hosts: len(c.Hosts), Managed: c.Managed, LastError: c.LastError})
	}
	writeJSON(w, http.StatusOK, d)
}
