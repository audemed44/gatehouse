package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audemed44/gatehouse/internal/config"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestRequestIDReachesTheApp(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Request-Id")
	}))
	defer up.Close()
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: up.URL, Enabled: true},
	}})
	do(p, "GET", "http://a.example.com/")
	if len(got) != 16 {
		t.Fatalf("new id %q", got)
	}
	do(p, "GET", "http://a.example.com/", func(r *http.Request) { r.Header.Set("X-Request-Id", "from-the-client") })
	if got != "from-the-client" {
		t.Fatalf("kept id %q", got)
	}
}

func TestFailedRequestLogged(t *testing.T) {
	buf := captureLogs(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	p, _ := newProxy(t, config.Config{Hosts: []config.Host{
		{Domains: []string{"a.example.com"}, Upstream: "http://" + addr, Enabled: true},
	}})
	do(p, "GET", "http://a.example.com/x?token=secret")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("one JSON line: %v %q", err, buf)
	}
	if line["level"] != "WARN" || line["msg"] != "upstream failed: a.example.com" || line["status"] != float64(502) ||
		!strings.Contains(line["err"].(string), "refused") || line["path"] != "/x" {
		t.Fatalf("line: %v", line)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Fatal("the query was logged")
	}
}
