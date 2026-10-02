// Package config is Gatehouse's routing configuration: proxy hosts,
// redirects and settings. It lives in one JSON file that is written
// atomically, and every change goes through Validate first, so a bad
// config is rejected whole and never half-applied.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is everything the proxy routes by. Certificates aren't here: they
// live as files in the data folder and are picked by SNI.
type Config struct {
	Hosts     []Host     `json:"hosts" yaml:"hosts"`
	Redirects []Redirect `json:"redirects" yaml:"redirects"`
	Settings  Settings   `json:"settings" yaml:"settings"`
}

// Host proxies one or more domains to an upstream.
type Host struct {
	ID      string   `json:"id" yaml:"id"`
	Domains []string `json:"domains" yaml:"domains"`
	// Upstream is a URL: http://container:port or https://host:port.
	Upstream string `json:"upstream" yaml:"upstream"`
	// InsecureUpstream skips verifying an HTTPS upstream's certificate
	// (self-signed admin panels like Cockpit).
	InsecureUpstream bool `json:"insecure_upstream,omitempty" yaml:"insecure_upstream,omitempty"`
	Enabled          bool `json:"enabled" yaml:"enabled"`
	ForceHTTPS       bool `json:"force_https,omitempty" yaml:"force_https,omitempty"`
	HSTS             bool `json:"hsts,omitempty" yaml:"hsts,omitempty"`
	// MaxBodyMB limits request bodies; 0 means no limit.
	MaxBodyMB int `json:"max_body_mb,omitempty" yaml:"max_body_mb,omitempty"`
	// Timeout is how long to wait for the upstream's response headers
	// ("60s"); empty means no limit, which suits slow uploads and exports.
	Timeout         string            `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty" yaml:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty" yaml:"response_headers,omitempty"`
	// Allow limits clients to these CIDRs or addresses (e.g. the tailnet's
	// 100.64.0.0/10); empty allows everyone.
	Allow     []string    `json:"allow,omitempty" yaml:"allow,omitempty"`
	BasicAuth []BasicUser `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	// IdleStop stops Container after this long without requests ("30m");
	// the next request starts it again. Empty keeps it running.
	IdleStop  string `json:"idle_stop,omitempty" yaml:"idle_stop,omitempty"`
	Container string `json:"container,omitempty" yaml:"container,omitempty"`
}

// BasicUser is a basic-auth login; Hash is bcrypt. The API takes Password
// instead and hashes it, and never returns either.
type BasicUser struct {
	User     string `json:"user" yaml:"user"`
	Hash     string `json:"hash,omitempty" yaml:"hash,omitempty"`
	Password string `json:"password,omitempty" yaml:"-"`
}

// Redirect sends one or more domains elsewhere.
type Redirect struct {
	ID      string   `json:"id" yaml:"id"`
	Domains []string `json:"domains" yaml:"domains"`
	// Target is a URL or a bare domain (https:// is assumed).
	Target string `json:"target" yaml:"target"`
	// Code is 301, 302, 307 or 308.
	Code         int  `json:"code" yaml:"code"`
	PreservePath bool `json:"preserve_path" yaml:"preserve_path"`
	Enabled      bool `json:"enabled" yaml:"enabled"`
	ForceHTTPS   bool `json:"force_https,omitempty" yaml:"force_https,omitempty"`
}

type Settings struct {
	// ACME account and DNS-01 provider for issuing certificates.
	ACMEEmail   string `json:"acme_email" yaml:"acme_email"`
	ACMEStaging bool   `json:"acme_staging" yaml:"acme_staging"`
	DNSProvider string `json:"dns_provider" yaml:"dns_provider"`
	// Resolvers check the TXT record has propagated before asking the CA to
	// look; public ones, since the host's resolver may be split-horizon.
	Resolvers []string `json:"resolvers" yaml:"resolvers"`
	// Certificates are renewed with RenewDays left and a warning is sent
	// with WarnDays left, whatever the cause.
	RenewDays int `json:"renew_days" yaml:"renew_days"`
	WarnDays  int `json:"warn_days" yaml:"warn_days"`
	// NotifyURL takes Apprise-style JSON (Lookout's /notify/<key>).
	NotifyURL string `json:"notify_url" yaml:"notify_url"`
	// Certificates to keep issued and renewed, e.g. [["*.example.com",
	// "example.com"]].
	Certificates [][]string `json:"certificates" yaml:"certificates"`
	// AccessLogSize is how many recent requests are kept in memory.
	AccessLogSize int `json:"access_log_size" yaml:"access_log_size"`
}

func Default() Config {
	c := Config{}
	c.Normalize()
	return c
}

// Normalize fills in defaults and tidies values; Validate checks them.
func (c *Config) Normalize() {
	if c.Hosts == nil {
		c.Hosts = []Host{}
	}
	if c.Redirects == nil {
		c.Redirects = []Redirect{}
	}
	s := &c.Settings
	if s.DNSProvider == "" {
		s.DNSProvider = "cloudflare"
	}
	if len(s.Resolvers) == 0 {
		s.Resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if s.RenewDays <= 0 {
		s.RenewDays = 30
	}
	if s.WarnDays <= 0 {
		s.WarnDays = 14
	}
	if s.AccessLogSize <= 0 {
		s.AccessLogSize = 1000
	}
	if s.Certificates == nil {
		s.Certificates = [][]string{}
	}
	for i := range s.Certificates {
		s.Certificates[i] = normDomains(s.Certificates[i])
	}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		h.Domains = normDomains(h.Domains)
		h.Upstream = strings.TrimSpace(h.Upstream)
		h.Container = strings.TrimSpace(h.Container)
		h.IdleStop = strings.TrimSpace(h.IdleStop)
		h.Timeout = strings.TrimSpace(h.Timeout)
		if h.ID == "" {
			h.ID = idFor(h.Domains)
		}
	}
	for i := range c.Redirects {
		r := &c.Redirects[i]
		r.Domains = normDomains(r.Domains)
		r.Target = strings.TrimSpace(r.Target)
		if r.Code == 0 {
			r.Code = 301
		}
		if r.ID == "" {
			r.ID = idFor(r.Domains)
		}
	}
}

func normDomains(in []string) []string {
	out := []string{}
	for _, d := range in {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// idFor derives a readable ID from the first domain.
func idFor(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return strings.NewReplacer("*", "wildcard", ".", "-").Replace(domains[0])
}

// Validate reports every problem at once, so the UI can show them together.
func (c *Config) Validate() error {
	var errs []error
	seenDomain := map[string]string{}
	seenID := map[string]bool{}
	claim := func(owner string, domains []string) {
		if len(domains) == 0 {
			errs = append(errs, fmt.Errorf("%s: add at least one domain", owner))
		}
		for _, d := range domains {
			if err := ValidDomain(d); err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", owner, err))
				continue
			}
			if other, ok := seenDomain[d]; ok {
				errs = append(errs, fmt.Errorf("%s: %s is already used by %s", owner, d, other))
				continue
			}
			seenDomain[d] = owner
		}
	}
	checkID := func(owner, id string) {
		if id == "" {
			return
		}
		if seenID[id] {
			errs = append(errs, fmt.Errorf("%s: the id %q is used twice", owner, id))
		}
		seenID[id] = true
	}
	for _, h := range c.Hosts {
		owner := "host " + label(h.ID, h.Domains)
		checkID(owner, h.ID)
		claim(owner, h.Domains)
		if _, err := ParseUpstream(h.Upstream); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", owner, err))
		}
		if h.MaxBodyMB < 0 {
			errs = append(errs, fmt.Errorf("%s: the body size limit can't be negative", owner))
		}
		if h.Timeout != "" {
			if d, err := time.ParseDuration(h.Timeout); err != nil || d <= 0 {
				errs = append(errs, fmt.Errorf("%s: timeout %q isn't a duration like 60s", owner, h.Timeout))
			}
		}
		for _, a := range h.Allow {
			if _, err := ParsePrefix(a); err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", owner, err))
			}
		}
		for name := range h.RequestHeaders {
			if !validHeaderName(name) {
				errs = append(errs, fmt.Errorf("%s: %q isn't a valid header name", owner, name))
			}
		}
		for name := range h.ResponseHeaders {
			if !validHeaderName(name) {
				errs = append(errs, fmt.Errorf("%s: %q isn't a valid header name", owner, name))
			}
		}
		for _, u := range h.BasicAuth {
			if u.User == "" || strings.Contains(u.User, ":") {
				errs = append(errs, fmt.Errorf("%s: basic auth needs a user name without a colon", owner))
			}
			if u.Hash == "" {
				errs = append(errs, fmt.Errorf("%s: basic auth user %s has no password", owner, u.User))
			}
		}
		if h.IdleStop != "" {
			d, err := time.ParseDuration(h.IdleStop)
			if err != nil || d < time.Minute {
				errs = append(errs, fmt.Errorf("%s: idle stop %q must be a duration of at least 1m", owner, h.IdleStop))
			}
			if h.Container == "" {
				errs = append(errs, fmt.Errorf("%s: idle stop needs the container to stop", owner))
			}
		}
	}
	for _, r := range c.Redirects {
		owner := "redirect " + label(r.ID, r.Domains)
		checkID(owner, r.ID)
		claim(owner, r.Domains)
		if _, err := RedirectTarget(r.Target); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", owner, err))
		}
		switch r.Code {
		case 301, 302, 307, 308:
		default:
			errs = append(errs, fmt.Errorf("%s: the code must be 301, 302, 307 or 308", owner))
		}
	}
	s := c.Settings
	if s.WarnDays >= s.RenewDays {
		errs = append(errs, errors.New("settings: warn when fewer days are left than when renewing, or renewals would always warn"))
	}
	if s.NotifyURL != "" {
		if u, err := url.Parse(s.NotifyURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("settings: the notify URL must be an http(s) URL"))
		}
	}
	for _, r := range s.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			errs = append(errs, fmt.Errorf("settings: resolver %q needs a port, like 1.1.1.1:53", r))
		}
	}
	for _, names := range s.Certificates {
		if len(names) == 0 {
			errs = append(errs, errors.New("settings: a certificate needs at least one domain"))
		}
		for _, d := range names {
			if err := ValidDomain(d); err != nil {
				errs = append(errs, fmt.Errorf("settings: certificate %v", err))
			}
		}
	}
	return errors.Join(errs...)
}

func label(id string, domains []string) string {
	if len(domains) > 0 {
		return domains[0]
	}
	if id != "" {
		return id
	}
	return "(new)"
}

// ValidDomain accepts host names and a leading wildcard label.
func ValidDomain(d string) error {
	name := strings.TrimPrefix(d, "*.")
	if name == "" || len(d) > 253 || strings.Contains(name, "*") {
		return fmt.Errorf("%q isn't a valid domain", d)
	}
	for _, part := range strings.Split(name, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return fmt.Errorf("%q isn't a valid domain", d)
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return fmt.Errorf("%q isn't a valid domain", d)
			}
		}
	}
	return nil
}

// ParseUpstream checks an upstream is http(s)://host:port with nothing else.
func ParseUpstream(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("set the upstream, like http://app:8080")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("upstream %q isn't a URL like http://app:8080", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream %q must be http or https", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("upstream %q should be just scheme, host and port", raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("upstream %q has an invalid port", raw)
		}
	}
	u.Path = ""
	return u, nil
}

// ParsePrefix takes a CIDR or a single address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q isn't a CIDR like 100.64.0.0/10", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q isn't an IP address or CIDR", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// RedirectTarget parses a redirect target, assuming https:// for a bare
// domain.
func RedirectTarget(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("set where to redirect to")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("redirect target %q isn't a URL", raw)
	}
	return u, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}

// Load reads the config file; a missing file gives the defaults.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically: a temporary file, fsynced, renamed
// over the old one. The previous version is kept as .bak.
func Save(path string, c Config) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gatehouse-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = copyFile(path, path+".bak")
	}
	return os.Rename(tmp.Name(), path)
}

func copyFile(from, to string) error {
	raw, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, raw, 0o600)
}

// Clone deep-copies the config so a caller can edit it without touching
// the one being served.
func (c Config) Clone() Config {
	raw, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(raw, &out)
	out.Normalize()
	return out
}
