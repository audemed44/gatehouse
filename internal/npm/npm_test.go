package npm

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
)

// fakeNPM lays out a folder like NPM's: data/database.sqlite and
// letsencrypt/live/npm-5 symlinked into archive/, as certbot does.
func fakeNPM(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	db, err := sql.Open("sqlite", filepath.Join(dir, "data", "database.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE proxy_host (id INTEGER, is_deleted INTEGER, domain_names TEXT, forward_host TEXT, forward_port INTEGER,
			access_list_id INTEGER, certificate_id INTEGER, ssl_forced INTEGER, block_exploits INTEGER, advanced_config TEXT,
			meta TEXT, allow_websocket_upgrade INTEGER, http2_support INTEGER, forward_scheme TEXT, enabled INTEGER,
			locations TEXT, hsts_enabled INTEGER, hsts_subdomains INTEGER)`,
		`CREATE TABLE redirection_host (id INTEGER, is_deleted INTEGER, domain_names TEXT, forward_domain_name TEXT,
			preserve_path INTEGER, certificate_id INTEGER, ssl_forced INTEGER, enabled INTEGER, forward_scheme TEXT, forward_http_code INTEGER)`,
		`CREATE TABLE certificate (id INTEGER, is_deleted INTEGER, provider TEXT, nice_name TEXT, domain_names TEXT, expires_on TEXT, meta TEXT)`,
		`CREATE TABLE stream (id INTEGER, is_deleted INTEGER)`,
		`CREATE TABLE dead_host (id INTEGER, is_deleted INTEGER)`,
		`CREATE TABLE access_list (id INTEGER, is_deleted INTEGER)`,
		`INSERT INTO proxy_host VALUES (1,0,'["books.example.com","shelfloom.example.com"]','172.17.0.1',8000,0,5,1,1,'','{}',1,0,'http',1,'[]',0,0)`,
		`INSERT INTO proxy_host VALUES (2,0,'["cockpit.example.com"]','172.17.0.1',9090,0,5,1,1,'','{}',1,0,'https',1,NULL,1,0)`,
		`INSERT INTO proxy_host VALUES (3,0,'["odd.example.com"]','172.17.0.1',1,2,5,0,1,'location /x {}','{}',1,0,'http',0,'[{"path":"/a"}]',0,0)`,
		`INSERT INTO proxy_host VALUES (4,1,'["deleted.example.com"]','x',1,0,0,0,0,'','{}',0,0,'http',1,'[]',0,0)`,
		`INSERT INTO redirection_host VALUES (1,0,'["old.example.com"]','books.example.com',1,0,1,1,'auto',301)`,
		`INSERT INTO certificate VALUES (5,0,'letsencrypt','wild','["*.example.com","example.com"]','2026-11-27 19:37:21',
			'{"dns_challenge":true,"dns_provider":"cloudflare","dns_provider_credentials":"dns_cloudflare_api_token = SECRET"}')`,
		`INSERT INTO stream VALUES (1,0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	certPEM, keyPEM := certs.SelfSigned([]string{"*.example.com", "example.com"}, time.Now().Add(50*24*time.Hour))
	archive := filepath.Join(dir, "letsencrypt", "archive", "npm-5")
	live := filepath.Join(dir, "letsencrypt", "live", "npm-5")
	os.MkdirAll(archive, 0o755)
	os.MkdirAll(live, 0o755)
	os.WriteFile(filepath.Join(archive, "fullchain4.pem"), certPEM, 0o644)
	os.WriteFile(filepath.Join(archive, "privkey4.pem"), keyPEM, 0o644)
	os.Symlink("../../archive/npm-5/fullchain4.pem", filepath.Join(live, "fullchain.pem"))
	os.Symlink("../../archive/npm-5/privkey4.pem", filepath.Join(live, "privkey.pem"))
	return dir
}

func TestReadAndApply(t *testing.T) {
	dir := fakeNPM(t)
	found, err := Read(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Hosts) != 3 || len(found.Redirects) != 1 || len(found.Certs) != 1 {
		t.Fatalf("found: %+v", found)
	}
	h := found.Hosts[0]
	if h.Upstream != "http://172.17.0.1:8000" || !h.Enabled || !h.ForceHTTPS || len(h.Domains) != 2 {
		t.Fatalf("host: %+v", h)
	}
	if c := found.Hosts[1]; !c.InsecureUpstream || !c.HSTS || c.Upstream != "https://172.17.0.1:9090" {
		t.Fatalf("https host: %+v", c)
	}
	if r := found.Redirects[0]; r.Target != "https://books.example.com" || !r.PreservePath || r.Code != 301 {
		t.Fatalf("redirect: %+v", r)
	}
	warnings := strings.Join(found.Warnings, "\n")
	for _, want := range []string{"custom nginx config", "custom locations", "access list", "1 streams"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("missing warning %q in %s", want, warnings)
		}
	}
	if !found.Certs[0].Found || found.Certs[0].DNS != "cloudflare" {
		t.Fatalf("cert: %+v", found.Certs[0])
	}

	store, _ := certs.Open(t.TempDir())
	cfg := config.Default()
	cfg.Hosts = []config.Host{{Domains: []string{"books.example.com"}, Upstream: "shelfloom:8000", Enabled: true}}
	cfg.Normalize()
	rep, err := found.Apply(&cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hosts != 2 || rep.Redirects != 1 || rep.Certs != 1 || len(rep.Skipped) != 1 {
		t.Fatalf("report: %+v", rep)
	}
	if cfg.Hosts[0].Upstream != "shelfloom:8000" {
		t.Fatal("overwrote an existing host")
	}
	if len(cfg.Settings.Certificates) != 1 || cfg.Settings.Certificates[0][0] != "*.example.com" || cfg.Settings.DNSProvider != "cloudflare" {
		t.Fatalf("renewal not set up: %+v", cfg.Settings)
	}
	if c, ok := store.Get("wildcard-example-com"); !ok || c.Source != "npm" {
		t.Fatalf("cert not imported: %+v", c)
	}
	// Importing again adds nothing.
	rep, err = found.Apply(&cfg, store)
	if err != nil || rep.Hosts != 0 || rep.Redirects != 0 || len(cfg.Settings.Certificates) != 1 {
		t.Fatalf("second import: %+v %v", rep, err)
	}
}

func TestMissingDatabase(t *testing.T) {
	if _, err := Read(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "mounted") {
		t.Fatalf("got %v", err)
	}
}
