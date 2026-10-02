package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/docker"
	"github.com/audemed44/gatehouse/internal/sleep"
)

// echo answers with what it received.
func echo(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "host=%s path=%s xff=%s proto=%s real=%s custom=%s auth=%s body=%d",
			r.Host, r.URL.RequestURI(), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Real-IP"), r.Header.Get("X-Custom"), r.Header.Get("Authorization"), len(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newProxy(t *testing.T, c config.Config) (*Proxy, *certs.Store) {
	t.Helper()
	store, err := certs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := New(store, nil, 100)
	c.Normalize()
	if err := p.Apply(c); err != nil {
		t.Fatal(err)
	}
	return p, store
}

func do(p http.Handler, method, url string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, nil)
	r.RemoteAddr = "100.100.1.2:5555"
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestRoutesByHost(t *testing.T) {
	up := echo(t)
	p, _ := newProxy(t, config.Config{
		Hosts: []config.Host{
			{Domains: []string{"books.example.com"}, Upstream: up.URL, Enabled: true,
				RequestHeaders: map[string]string{"X-Custom": "1"}, ResponseHeaders: map[string]string{"X-Frame-Options": "SAMEORIGIN"}},
			{Domains: []string{"*.apps.example.com"}, Upstream: up.URL, Enabled: true},
			{Domains: []string{"off.example.com"}, Upstream: up.URL, Enabled: false},
		},
		Redirects: []config.Redirect{
			{Domains: []string{"old.example.com"}, Target: "new.example.com", Code: 302, PreservePath: true, Enabled: true},
			{Domains: []string{"home.example.com"}, Target: "https://books.example.com/start", Enabled: true},
		},
	})

	w := do(p, "GET", "http://Books.Example.com/a?b=1", func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "6.6.6.6") // spoofed, must not pass
	})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "host=Books.Example.com path=/a?b=1 xff=100.100.1.2 proto=http real=100.100.1.2 custom=1") {
		t.Fatalf("proxied: %d %s", w.Code, body)
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" || w.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("headers: %v", w.Header())
	}
	if w := do(p, "GET", "http://x.apps.example.com/"); w.Code != 200 {
		t.Fatalf("wildcard: %d", w.Code)
	}
	if w := do(p, "GET", "http://off.example.com/"); w.Code != 404 {
		t.Fatalf("disabled host: %d", w.Code)
	}
	if w := do(p, "GET", "http://nope.example.com/"); w.Code != 404 || !strings.Contains(w.Body.String(), "nope.example.com") {
		t.Fatalf("unknown host: %d", w.Code)
	}
	w = do(p, "GET", "http://old.example.com/x/y?z=1")
	if w.Code != 302 || w.Header().Get("Location") != "https://new.example.com/x/y?z=1" {
		t.Fatalf("redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = do(p, "GET", "http://home.example.com/x")
	if w.Code != 301 || w.Header().Get("Location") != "https://books.example.com/start" {
		t.Fatalf("redirect without path: %d %s", w.Code, w.Header().Get("Location"))
	}

	entries := p.Log.Query("", false, 10)
	if len(entries) != 6 || entries[0].Host != "home.example.com" || entries[len(entries)-1].Path != "/a" {
		t.Fatalf("access log: %+v", entries)
	}
}

func TestForceHTTPSAndHSTS(t *testing.T) {
	up := echo(t)
	p, store := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: up.URL, Enabled: true, ForceHTTPS: true, HSTS: true},
	}})
	// No certificate yet: plain HTTP keeps working rather than redirecting
	// to a broken HTTPS.
	if w := do(p, "GET", "http://a.example.com/"); w.Code != 200 {
		t.Fatalf("no cert: %d", w.Code)
	}
	c, k := certs.SelfSigned([]string{"*.example.com"}, time.Now().Add(48*time.Hour))
	if _, err := store.Put("wild", c, k, "upload"); err != nil {
		t.Fatal(err)
	}
	w := do(p, "GET", "http://a.example.com/p?q=1")
	if w.Code != 301 || w.Header().Get("Location") != "https://a.example.com/p?q=1" {
		t.Fatalf("force https: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do(p, "POST", "http://a.example.com/p"); w.Code != 308 {
		t.Fatalf("POST should keep its method: %d", w.Code)
	}
	w = do(p, "GET", "https://a.example.com/", func(r *http.Request) { r.TLS = &tls.ConnectionState{} })
	if w.Code != 200 || w.Header().Get("Strict-Transport-Security") == "" || !strings.Contains(w.Body.String(), "proto=https") {
		t.Fatalf("https: %d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestAllowAndBasicAuth(t *testing.T) {
	up := echo(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: up.URL, Enabled: true, Allow: []string{"100.64.0.0/10"}},
		{Domains: []string{"b.example.com"}, Upstream: up.URL, Enabled: true, Allow: []string{"10.0.0.0/8"}},
		{Domains: []string{"c.example.com"}, Upstream: up.URL, Enabled: true,
			BasicAuth: []config.BasicUser{{User: "me", Hash: string(hash)}}},
	}})
	if w := do(p, "GET", "http://a.example.com/"); w.Code != 200 {
		t.Fatalf("allowed: %d", w.Code)
	}
	if w := do(p, "GET", "http://b.example.com/"); w.Code != 403 {
		t.Fatalf("not allowed: %d", w.Code)
	}
	w := do(p, "GET", "http://c.example.com/")
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no auth: %d", w.Code)
	}
	if w := do(p, "GET", "http://c.example.com/", func(r *http.Request) { r.SetBasicAuth("me", "wrong") }); w.Code != 401 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	for range 2 { // second time from the cache
		w = do(p, "GET", "http://c.example.com/", func(r *http.Request) { r.SetBasicAuth("me", "s3cret") })
		if w.Code != 200 || !strings.Contains(w.Body.String(), "auth= ") {
			t.Fatalf("auth: %d %s", w.Code, w.Body)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	up := echo(t)
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: up.URL, Enabled: true, MaxBodyMB: 1},
	}})
	big := strings.Repeat("x", 2<<20)
	r := httptest.NewRequest("POST", "http://a.example.com/up", strings.NewReader(big))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("declared length: %d", w.Code)
	}
	// Chunked, so the length isn't known up front.
	r = httptest.NewRequest("POST", "http://a.example.com/up", io.MultiReader(strings.NewReader(big)))
	r.ContentLength = -1
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("streamed: %d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("POST", "http://a.example.com/up", strings.NewReader("small"))
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "body=5") {
		t.Fatalf("small: %d %s", w.Code, w.Body)
	}
}

func TestBadReloadKeepsServing(t *testing.T) {
	up := echo(t)
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: up.URL, Enabled: true},
	}})
	bad := p.Config().Clone()
	bad.Hosts = append(bad.Hosts, config.Host{Domains: []string{"a.example.com"}, Upstream: "x:1", Enabled: true})
	if err := p.Apply(bad); err == nil {
		t.Fatal("applied a config with a duplicate domain")
	}
	if w := do(p, "GET", "http://a.example.com/"); w.Code != 200 {
		t.Fatalf("old config lost: %d", w.Code)
	}
}

func TestUpstreamDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: "http://" + addr, Enabled: true},
	}})
	w := do(p, "GET", "http://a.example.com/")
	if w.Code != 502 || !strings.Contains(w.Body.String(), "answering") {
		t.Fatalf("down: %d %s", w.Code, w.Body)
	}
}

// TestWebSocketAndStreaming runs over real listeners: hijacking needs them.
func TestWebSocketAndStreaming(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", 400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()
		line, _ := brw.ReadString('\n')
		brw.WriteString("echo:" + line)
		brw.Flush()
	}))
	defer up.Close()
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"ws.example.com"}, Upstream: up.URL, Enabled: true},
	}})
	front := httptest.NewServer(p)
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	fmt.Fprintf(conn, "hello\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := br.ReadString('\n')
	if line != "echo:hello\n" {
		t.Fatalf("websocket echo: %q", line)
	}
	conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e := p.Log.Query("ws.example.com", false, 1); len(e) == 1 {
			if e[0].Status != 101 {
				t.Fatalf("logged status %d", e[0].Status)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("websocket not logged")
}

type fakeDocker struct {
	mu      sync.Mutex
	running bool
	starts  int
	stops   int
	onStart func()
}

func (f *fakeDocker) State(context.Context, string) (docker.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running {
		return docker.State{Running: true, Status: "running"}, nil
	}
	return docker.State{Status: "exited"}, nil
}

func (f *fakeDocker) Start(context.Context, string) error {
	f.mu.Lock()
	f.running = true
	f.starts++
	cb := f.onStart
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
	return nil
}

func (f *fakeDocker) Stop(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = false
	f.stops++
	return nil
}

func TestScaleToZero(t *testing.T) {
	// The upstream only listens while the fake container runs.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	var srv *http.Server
	fd := &fakeDocker{running: true}
	listen := func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Error(err)
			return
		}
		srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "app") })}
		go srv.Serve(l)
	}
	listen()
	fd.onStart = listen

	dir := t.TempDir()
	sl := sleep.New(fd, filepath.Join(dir, "sleeping.json"))
	store, _ := certs.Open(filepath.Join(dir, "certs"))
	p := New(store, sl, 100)
	c := config.Config{Hosts: []config.Host{{
		Domains: []string{"app.example.com"}, Upstream: "http://" + addr, Enabled: true, IdleStop: "1m", Container: "app",
	}}}
	c.Normalize()
	if err := p.Apply(c); err != nil {
		t.Fatal(err)
	}
	if w := do(p, "GET", "http://app.example.com/"); w.Code != 200 {
		t.Fatalf("awake: %d", w.Code)
	}
	// Not idle long enough: stays up.
	sl.StopIdle(context.Background())
	if fd.stops != 0 {
		t.Fatal("stopped too early")
	}
	// Idle: stopped.
	if err := sl.Sleep(context.Background(), "app"); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if st, _ := sl.Status("app"); st.State != sleep.Sleeping || fd.stops != 1 {
		t.Fatalf("not asleep: %+v", st)
	}
	// A restart remembers it's asleep.
	if st, _ := sleep.New(fd, filepath.Join(dir, "sleeping.json")).Status("app"); st.State != sleep.Sleeping {
		t.Fatalf("restart forgot: %+v", st)
	}

	// A monitor's probe neither wakes it nor gets the waking page.
	w := do(p, "GET", "http://app.example.com/", func(r *http.Request) { r.Header.Set(ProbeHeader, "1") })
	if w.Code != 503 || w.Header().Get(StateHeader) != "sleeping" || fd.starts != 0 {
		t.Fatalf("probe while asleep: %d %v starts=%d", w.Code, w.Header(), fd.starts)
	}

	// A browser gets the waking page; the container is started.
	w = do(p, "GET", "http://app.example.com/", func(r *http.Request) { r.Header.Set("Accept", "text/html") })
	if w.Code != 503 || !strings.Contains(w.Body.String(), "Waking up") || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("waking page: %d %s", w.Code, w.Body)
	}
	// An API call waits for it instead.
	w = do(p, "GET", "http://app.example.com/api")
	if w.Code != 200 || w.Body.String() != "app" {
		t.Fatalf("api after wake: %d %s", w.Code, w.Body)
	}
	if fd.starts != 1 {
		t.Fatalf("started %d times", fd.starts)
	}
	if st, _ := sl.Status("app"); st.State != sleep.Awake {
		t.Fatalf("state: %+v", st)
	}
	// While awake, a probe goes through but doesn't count as activity.
	before, _ := sl.Status("app")
	time.Sleep(5 * time.Millisecond)
	if w := do(p, "GET", "http://app.example.com/", func(r *http.Request) { r.Header.Set(ProbeHeader, "1") }); w.Code != 200 {
		t.Fatalf("probe while awake: %d", w.Code)
	}
	if after, _ := sl.Status("app"); !after.LastActive.Equal(before.LastActive) {
		t.Fatal("a probe counted as activity")
	}
	srv.Close()

	// Stopped behind Gatehouse's back: the refused connection is noticed,
	// and the request wakes it.
	fd.mu.Lock()
	fd.running = false
	fd.mu.Unlock()
	w = do(p, "GET", "http://app.example.com/", func(r *http.Request) { r.Header.Set("Accept", "text/html") })
	if w.Code != 503 || !strings.Contains(w.Body.String(), "Waking up") {
		t.Fatalf("stopped elsewhere: %d %s", w.Code, w.Body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := sl.Status("app"); st.State == sleep.Awake {
			srv.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("never woke")
}
