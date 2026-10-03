package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/proxy"
	"github.com/audemed44/gatehouse/internal/sleep"
)

type issuer struct{ calls chan []string }

func (i *issuer) Obtain(_ context.Context, domains []string, _ config.Settings) ([]byte, []byte, error) {
	c, k := certs.SelfSigned(domains, time.Now().Add(90*24*time.Hour))
	i.calls <- domains
	return c, k, nil
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	proxy  *proxy.Proxy
	store  *certs.Store
	issuer *issuer
	dir    string
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	store, _ := certs.Open(filepath.Join(dir, "certs"))
	sl := sleep.New(nil, "")
	p := proxy.New(store, sl, 50)
	if err := p.Apply(config.Default()); err != nil {
		t.Fatal(err)
	}
	is := &issuer{calls: make(chan []string, 4)}
	m := certs.NewManager(store, is, func() config.Settings { return p.Config().Settings })
	s := New(Options{
		ConfigPath: filepath.Join(dir, "gatehouse.json"), Proxy: p, Certs: store, Manager: m, Sleep: sl,
		Token: "admin-token", DiscoveryToken: "read-only", FoyerURL: "https://home.example", Web: fstest.MapFS{"index.html": {Data: []byte("<!doctype html>app")}},
	})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, proxy: p, store: store, issuer: is, dir: dir}
}

func (e *env) call(method, path, token string, body any) (int, string) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestAuth(t *testing.T) {
	e := setup(t)
	if code, _ := e.call("GET", "/api/hosts", "", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.call("GET", "/api/hosts", "read-only", nil); code != 401 {
		t.Fatalf("discovery token on admin API: %d", code)
	}
	if code, _ := e.call("GET", "/api/discovery", "read-only", nil); code != 200 {
		t.Fatalf("discovery token: %d", code)
	}
	if code, _ := e.call("GET", "/api/discovery", "admin-token", nil); code != 200 {
		t.Fatalf("admin token on discovery: %d", code)
	}
	if code, body := e.call("GET", "/api/session", "", nil); code != 200 || body != `{"authenticated":false,"foyer_url":"https://home.example"}`+"\n" {
		t.Fatalf("session: %d %s", code, body)
	}
	// Browser sign-in sets a cookie that works.
	resp, err := http.Post(e.srv.URL+"/api/session", "application/json", strings.NewReader(`{"token":"admin-token"}`))
	if err != nil || resp.StatusCode != 200 || len(resp.Cookies()) != 1 {
		t.Fatalf("login: %v %v", resp, err)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/hosts", nil)
	req.AddCookie(resp.Cookies()[0])
	if r2, _ := http.DefaultClient.Do(req); r2.StatusCode != 200 {
		t.Fatalf("cookie: %d", r2.StatusCode)
	}
	// Another site can't post with the cookie.
	req, _ = http.NewRequest("POST", e.srv.URL+"/api/hosts", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(resp.Cookies()[0])
	if r3, _ := http.DefaultClient.Do(req); r3.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", r3.StatusCode)
	}
	if code, body := e.call("GET", "/hosts", "", nil); code != 200 || !strings.Contains(body, "app") {
		t.Fatalf("spa: %d %s", code, body)
	}
}

func TestHostsLifecycle(t *testing.T) {
	e := setup(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "up") }))
	defer up.Close()

	host := map[string]any{
		"domains": []string{"books.example.com"}, "upstream": up.URL, "enabled": true,
		"basic_auth": []map[string]string{{"user": "me", "password": "pw"}},
	}
	code, body := e.call("POST", "/api/hosts", "admin-token", host)
	if code != 200 || !strings.Contains(body, `"id":"books-example-com"`) || strings.Contains(body, "$2a$") {
		t.Fatalf("create: %d %s", code, body)
	}
	// Saved to disk and served.
	saved, err := config.Load(filepath.Join(e.dir, "gatehouse.json"))
	if err != nil || len(saved.Hosts) != 1 || !strings.HasPrefix(saved.Hosts[0].BasicAuth[0].Hash, "$2a$") {
		t.Fatalf("saved: %+v %v", saved, err)
	}
	// Same domains again: refused, nothing changes.
	code, body = e.call("POST", "/api/hosts", "admin-token", map[string]any{"domains": []string{"books.example.com"}, "upstream": "x:1", "enabled": true})
	if code != 422 || !strings.Contains(body, "already used") {
		t.Fatalf("duplicate: %d %s", code, body)
	}
	if len(e.proxy.Config().Hosts) != 1 {
		t.Fatal("bad change applied")
	}
	// Editing without a password keeps the old hash.
	host["basic_auth"] = []map[string]string{{"user": "me"}}
	host["hsts"] = true
	if code, body := e.call("PUT", "/api/hosts/books-example-com", "admin-token", host); code != 200 {
		t.Fatalf("edit: %d %s", code, body)
	}
	h := e.proxy.Config().Hosts[0]
	if !h.HSTS || h.BasicAuth[0].Hash != saved.Hosts[0].BasicAuth[0].Hash {
		t.Fatalf("edit lost the hash: %+v", h)
	}
	// Test reaches the upstream and reports DNS.
	code, body = e.call("POST", "/api/hosts/test", "admin-token", map[string]any{"domains": []string{"localhost"}, "upstream": up.URL})
	if code != 200 || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("test: %d %s", code, body)
	}
	// Discovery describes it.
	_, body = e.call("GET", "/api/discovery", "read-only", nil)
	var d Discovery
	json.Unmarshal([]byte(body), &d)
	if len(d.Hosts) != 1 || d.Hosts[0].ForwardHost != "127.0.0.1" || d.Hosts[0].HTTPS || d.Hosts[0].State != "awake" {
		t.Fatalf("discovery: %s", body)
	}
	if code, _ := e.call("DELETE", "/api/hosts/books-example-com", "admin-token", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.call("DELETE", "/api/hosts/books-example-com", "admin-token", nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
}

func TestRedirects(t *testing.T) {
	e := setup(t)
	code, body := e.call("POST", "/api/redirects", "admin-token", map[string]any{"domains": []string{"Old.Example.com"}, "target": "new.example.com", "enabled": true})
	if code != 200 || !strings.Contains(body, `"code":301`) || !strings.Contains(body, `"old.example.com"`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := e.call("PUT", "/api/redirects/old-example-com", "admin-token", map[string]any{"domains": []string{"old.example.com"}, "target": "x.example.com", "code": 418}); code != 422 {
		t.Fatalf("bad code accepted: %d", code)
	}
}

func TestCertificates(t *testing.T) {
	e := setup(t)
	code, body := e.call("POST", "/api/certificates", "admin-token", map[string]any{"domains": []string{"*.example.com", "example.com"}})
	if code != 202 {
		t.Fatalf("request: %d %s", code, body)
	}
	select {
	case got := <-e.issuer.calls:
		if got[0] != "*.example.com" {
			t.Fatalf("issued %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not issued")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, body = e.call("GET", "/api/certificates", "admin-token", nil)
		if strings.Contains(body, `"managed":true`) && strings.Contains(body, `"missing":false`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificates: %s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(e.proxy.Config().Settings.Certificates) != 1 {
		t.Fatal("not added to the renewal list")
	}
	// Settings saves keep the certificate list.
	s := e.proxy.Config().Settings
	s.ACMEEmail = "me@example.com"
	s.Certificates = nil
	if code, body := e.call("PUT", "/api/settings", "admin-token", s); code != 200 || !strings.Contains(body, "me@example.com") {
		t.Fatalf("settings: %d %s", code, body)
	}
	if len(e.proxy.Config().Settings.Certificates) != 1 {
		t.Fatal("settings dropped the certificate list")
	}
	if code, _ := e.call("DELETE", "/api/certificates/wildcard-example-com", "admin-token", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if len(e.store.List()) != 0 || len(e.proxy.Config().Settings.Certificates) != 0 {
		t.Fatal("not deleted")
	}
}

func TestConfigExportImport(t *testing.T) {
	e := setup(t)
	e.call("POST", "/api/hosts", "admin-token", map[string]any{"domains": []string{"a.example.com"}, "upstream": "a:80", "enabled": true})
	code, yaml := e.call("GET", "/api/config", "admin-token", nil)
	if code != 200 || !strings.Contains(yaml, "a.example.com") {
		t.Fatalf("export: %d %s", code, yaml)
	}
	e.call("DELETE", "/api/hosts/a-example-com", "admin-token", nil)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/config", strings.NewReader(yaml))
	req.Header.Set("Authorization", "Bearer admin-token")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 || len(e.proxy.Config().Hosts) != 1 {
		t.Fatalf("import: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", e.srv.URL+"/api/config", strings.NewReader("hosts:\n  - domains: [bad domain]\n    upstream: x:1\n"))
	req.Header.Set("Authorization", "Bearer admin-token")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 422 || len(e.proxy.Config().Hosts) != 1 {
		t.Fatalf("bad import: %d", resp.StatusCode)
	}
}

func TestNPMNotMounted(t *testing.T) {
	e := setup(t)
	if code, body := e.call("GET", "/api/npm", "admin-token", nil); code != 409 || !strings.Contains(body, "GATEHOUSE_NPM_DIR") {
		t.Fatalf("npm: %d %s", code, body)
	}
	if code, body := e.call("GET", "/api/foyer/widget", "admin-token", nil); code != 200 || !strings.Contains(body, `"version":1`) {
		t.Fatalf("widget: %d %s", code, body)
	}
}
