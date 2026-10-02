// Package npm imports Nginx Proxy Manager's setup: proxy hosts, redirects
// and certificates, read from its data folder (mounted read-only). NPM's
// files are never changed, so it can be switched back on at any time.
//
// DNS provider credentials in NPM's database are never read.
package npm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure Go, so the build stays static

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
)

// Found is what an NPM folder holds, converted.
type Found struct {
	Hosts     []config.Host     `json:"hosts"`
	Redirects []config.Redirect `json:"redirects"`
	Certs     []Cert            `json:"certificates"`
	Warnings  []string          `json:"warnings"`
}

// Cert is an NPM certificate and where its files are. The PEM is loaded
// only when importing and never returned.
type Cert struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	Provider string   `json:"provider"` // letsencrypt or other
	Expires  string   `json:"expires"`
	DNS      string   `json:"dns_provider,omitempty"`
	Found    bool     `json:"found"` // the PEM files are there
	dir      string
}

// Paths finds the database and certificate folders under dir, which may be
// NPM's root (with data/ and letsencrypt/) or its data folder.
func paths(dir string) (db, letsencrypt, custom string, err error) {
	for _, base := range []string{filepath.Join(dir, "data"), dir} {
		if _, err := os.Stat(filepath.Join(base, "database.sqlite")); err == nil {
			db = filepath.Join(base, "database.sqlite")
			custom = filepath.Join(base, "custom_ssl")
			break
		}
	}
	if db == "" {
		return "", "", "", fmt.Errorf("no database.sqlite in %s or %s/data (is NPM's folder mounted?)", dir, dir)
	}
	for _, le := range []string{filepath.Join(dir, "letsencrypt"), filepath.Join(filepath.Dir(filepath.Dir(db)), "letsencrypt"), "/etc/letsencrypt"} {
		if _, err := os.Stat(filepath.Join(le, "live")); err == nil {
			letsencrypt = le
			break
		}
	}
	return db, letsencrypt, custom, nil
}

// Read converts NPM's setup without changing anything.
func Read(ctx context.Context, dir string) (*Found, error) {
	dbPath, le, custom, err := paths(dir)
	if err != nil {
		return nil, err
	}
	// Read a copy: NPM may be writing, and the mount is read-only.
	tmp, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	db, err := sql.Open("sqlite", "file:"+tmp+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	f := &Found{Hosts: []config.Host{}, Redirects: []config.Redirect{}, Certs: []Cert{}, Warnings: []string{}}
	if err := f.readHosts(ctx, db); err != nil {
		return nil, fmt.Errorf("proxy hosts: %w", err)
	}
	if err := f.readRedirects(ctx, db); err != nil {
		return nil, fmt.Errorf("redirects: %w", err)
	}
	if err := f.readCerts(ctx, db, le, custom); err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	for _, t := range []struct{ table, what string }{
		{"stream", "streams (TCP/UDP forwarding) aren't supported"},
		{"dead_host", "404 hosts aren't imported: unknown names get Gatehouse's 404 page"},
		{"access_list", "access lists aren't imported: use each host's allowlist and basic auth"},
	} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+t.table+` WHERE is_deleted = 0`).Scan(&n); err == nil && n > 0 {
			f.Warnings = append(f.Warnings, fmt.Sprintf("%d %s", n, t.what))
		}
	}
	return f, nil
}

func copyToTemp(path string) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp("", "npm-*.sqlite")
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

func domains(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func (f *Found) readHosts(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT domain_names, forward_scheme, forward_host, forward_port, enabled, ssl_forced,
		       hsts_enabled, access_list_id, COALESCE(advanced_config, ''), COALESCE(locations, '')
		FROM proxy_host WHERE is_deleted = 0 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var names, scheme, host, advanced, locations string
		var port, enabled, forced, hsts, acl int
		if err := rows.Scan(&names, &scheme, &host, &port, &enabled, &forced, &hsts, &acl, &advanced, &locations); err != nil {
			return err
		}
		h := config.Host{
			Domains:  domains(names),
			Upstream: scheme + "://" + host + ":" + strconv.Itoa(port),
			// nginx doesn't verify upstream certificates by default
			InsecureUpstream: scheme == "https",
			Enabled:          enabled == 1,
			ForceHTTPS:       forced == 1,
			HSTS:             hsts == 1,
		}
		first := strings.Join(h.Domains, ", ")
		if strings.TrimSpace(advanced) != "" {
			f.Warnings = append(f.Warnings, first+": has custom nginx config, which isn't imported")
		}
		if l := strings.TrimSpace(locations); l != "" && l != "[]" && l != "null" {
			f.Warnings = append(f.Warnings, first+": has custom locations, which aren't imported")
		}
		if acl != 0 {
			f.Warnings = append(f.Warnings, first+": uses an access list; set its allowlist or basic auth in Gatehouse")
		}
		f.Hosts = append(f.Hosts, h)
	}
	return rows.Err()
}

func (f *Found) readRedirects(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT domain_names, forward_scheme, forward_domain_name, forward_http_code, preserve_path, enabled, ssl_forced
		FROM redirection_host WHERE is_deleted = 0 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var names, scheme, target string
		var code, preserve, enabled, forced int
		if err := rows.Scan(&names, &scheme, &target, &code, &preserve, &enabled, &forced); err != nil {
			return err
		}
		if scheme == "" || scheme == "auto" || scheme == "$scheme" {
			scheme = "https"
		}
		switch code {
		case 301, 302, 307, 308:
		default:
			code = 302
		}
		f.Redirects = append(f.Redirects, config.Redirect{
			Domains: domains(names), Target: scheme + "://" + target, Code: code,
			PreservePath: preserve == 1, Enabled: enabled == 1, ForceHTTPS: forced == 1,
		})
	}
	return rows.Err()
}

func (f *Found) readCerts(ctx context.Context, db *sql.DB, le, custom string) error {
	// Only the provider's name is read from meta, never its credentials.
	rows, err := db.QueryContext(ctx, `
		SELECT id, provider, domain_names, COALESCE(expires_on, ''),
		       COALESCE(json_extract(meta, '$.dns_provider'), '')
		FROM certificate WHERE is_deleted = 0 ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var provider, names, expires, dns string
		if err := rows.Scan(&id, &provider, &names, &expires, &dns); err != nil {
			return err
		}
		c := Cert{Domains: domains(names), Provider: provider, Expires: expires, DNS: dns}
		c.Name = certs.NameFor(c.Domains)
		folder := "npm-" + strconv.Itoa(id)
		if provider == "letsencrypt" {
			if le != "" {
				c.dir = filepath.Join(le, "live", folder)
			}
		} else {
			c.dir = filepath.Join(custom, folder)
		}
		if c.dir != "" {
			_, err1 := os.Stat(filepath.Join(c.dir, "fullchain.pem"))
			_, err2 := os.Stat(filepath.Join(c.dir, "privkey.pem"))
			c.Found = err1 == nil && err2 == nil
		}
		if !c.Found {
			f.Warnings = append(f.Warnings, fmt.Sprintf("certificate %s: files not found (mount NPM's letsencrypt folder too)", strings.Join(c.Domains, ", ")))
		}
		f.Certs = append(f.Certs, c)
	}
	return rows.Err()
}

// Report says what an import did.
type Report struct {
	Hosts     int      `json:"hosts"`
	Redirects int      `json:"redirects"`
	Certs     int      `json:"certificates"`
	Skipped   []string `json:"skipped"`
	Warnings  []string `json:"warnings"`
}

// Apply merges what was found into cfg and copies certificates into the
// store. Domains Gatehouse already serves are skipped, so importing twice
// changes nothing. Let's Encrypt certificates are added to the renewal
// list, and their DNS provider is used if Gatehouse supports it.
func (f *Found) Apply(cfg *config.Config, store *certs.Store) (Report, error) {
	rep := Report{Skipped: []string{}, Warnings: append([]string{}, f.Warnings...)}
	taken := map[string]bool{}
	for _, h := range cfg.Hosts {
		for _, d := range h.Domains {
			taken[d] = true
		}
	}
	for _, r := range cfg.Redirects {
		for _, d := range r.Domains {
			taken[d] = true
		}
	}
	free := func(ds []string) bool {
		for _, d := range ds {
			if taken[strings.ToLower(d)] {
				return false
			}
		}
		for _, d := range ds {
			taken[strings.ToLower(d)] = true
		}
		return true
	}
	for _, h := range f.Hosts {
		if !free(h.Domains) {
			rep.Skipped = append(rep.Skipped, strings.Join(h.Domains, ", ")+" (already set up)")
			continue
		}
		cfg.Hosts = append(cfg.Hosts, h)
		rep.Hosts++
	}
	for _, r := range f.Redirects {
		if !free(r.Domains) {
			rep.Skipped = append(rep.Skipped, strings.Join(r.Domains, ", ")+" (already set up)")
			continue
		}
		cfg.Redirects = append(cfg.Redirects, r)
		rep.Redirects++
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return rep, err
	}
	var errs []error
	for _, c := range f.Certs {
		if !c.Found {
			continue
		}
		if existing, ok := store.Get(c.Name); ok && existing.Source != "npm" {
			rep.Skipped = append(rep.Skipped, "certificate "+c.Name+" (Gatehouse already has one)")
			continue
		}
		chain, err1 := os.ReadFile(filepath.Join(c.dir, "fullchain.pem"))
		key, err2 := os.ReadFile(filepath.Join(c.dir, "privkey.pem"))
		if err := errors.Join(err1, err2); err != nil {
			errs = append(errs, fmt.Errorf("certificate %s: %w", c.Name, err))
			continue
		}
		if _, err := store.Put(c.Name, chain, key, "npm"); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("certificate %s: %v", c.Name, err))
			continue
		}
		rep.Certs++
		if c.Provider == "letsencrypt" {
			if !containsSet(cfg.Settings.Certificates, c.Domains) {
				cfg.Settings.Certificates = append(cfg.Settings.Certificates, c.Domains)
			}
			for _, p := range certs.Providers {
				if p == c.DNS {
					cfg.Settings.DNSProvider = p
				}
			}
		}
	}
	cfg.Normalize()
	return rep, errors.Join(errs...)
}

func containsSet(sets [][]string, want []string) bool {
	for _, s := range sets {
		if len(s) != len(want) {
			continue
		}
		same := true
		for i := range s {
			if !strings.EqualFold(s[i], want[i]) {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}
