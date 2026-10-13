package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is safe to write from handlers while a test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

// testLogger makes the default logger write JSON to a buffer, with a clock
// the test moves.
func testLogger(t *testing.T, level slog.Level) (*syncBuffer, *limiter, *time.Time) {
	t.Helper()
	buf := &syncBuffer{}
	l, lim := build("test", buf, level, false)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	lim.now = func() time.Time { return now }
	old := slog.Default()
	slog.SetDefault(l)
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf, lim, &now
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"": slog.LevelInfo, "DEBUG": slog.LevelDebug, "warn": slog.LevelWarn,
		"error": slog.LevelError, "nonsense": slog.LevelInfo,
	} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRedactAndTruncate(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelInfo)
	slog.Info("hello", "api_token", "abc", "Password", "hunter2", "err", strings.Repeat("x", maxValue+100), "id", 7)
	m := buf.lines(t)[0]
	if m["app"] != "test" || m["msg"] != "hello" || m["id"] != float64(7) {
		t.Fatalf("line: %v", m)
	}
	if m["api_token"] != "[redacted]" || m["Password"] != "[redacted]" {
		t.Fatalf("secrets written: %v", m)
	}
	if e := m["err"].(string); len(e) > maxValue+50 || !strings.HasSuffix(e, "[truncated]") {
		t.Fatalf("err not truncated: %d bytes", len(e))
	}
}

func TestRepeatsSuppressed(t *testing.T) {
	buf, _, now := testLogger(t, slog.LevelInfo)
	for range 500 {
		slog.Error("database is locked")
	}
	slog.Info("something else")
	if n := len(buf.lines(t)); n != perMessage+1 {
		t.Fatalf("%d lines written in the window, want %d", n, perMessage+1)
	}
	*now = now.Add(window)
	slog.Error("database is locked")
	lines := buf.lines(t)
	sum := lines[perMessage+1]
	if sum["kind"] != "suppressed" || sum["suppressed"] != float64(500-perMessage) || sum["of"] != "database is locked" || sum["app"] != "test" {
		t.Fatalf("summary: %v", sum)
	}
	if last := lines[len(lines)-1]; last["msg"] != "database is locked" {
		t.Fatalf("new window didn't let the message through: %v", last)
	}
}

func TestWindowCap(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelInfo)
	for i := range perWindow * 2 {
		slog.Info("item", "n", i)
		slog.Info("distinct " + strings.Repeat("x", i%300))
	}
	if n := len(buf.lines(t)); n != perWindow {
		t.Fatalf("%d lines, want the cap of %d", n, perWindow)
	}
}

func TestQuietWindowSummary(t *testing.T) {
	buf, lim, now := testLogger(t, slog.LevelInfo)
	for range perMessage + 5 {
		slog.Warn("retrying")
	}
	*now = now.Add(window)
	// What run does on each tick.
	lim.mu.Lock()
	rs := lim.rollover(lim.now())
	lim.mu.Unlock()
	lim.write(rs)
	lines := buf.lines(t)
	if last := lines[len(lines)-1]; last["suppressed"] != float64(5) {
		t.Fatalf("summary: %v", last)
	}
}

func TestRequests(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelDebug)
	h := Requests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetUser(r.Context(), "aakash")
		slog.InfoContext(r.Context(), "inside")
		switch r.URL.Path {
		case "/boom":
			panic("kaboom")
		case "/missing":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("ok"))
		}
	}))

	req := httptest.NewRequest("POST", "/api/items?token=secret", nil)
	req.Header.Set("X-Request-Id", "abc-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-Id") != "abc-123" {
		t.Fatal("trace not sent back")
	}
	lines := buf.lines(t)
	inside, reqLine := lines[0], lines[1]
	if inside["trace"] != "abc-123" || inside["user"] != "aakash" {
		t.Fatalf("inside line: %v", inside)
	}
	if reqLine["kind"] != "request" || reqLine["status"] != float64(201) || reqLine["bytes"] != float64(2) ||
		reqLine["path"] != "/api/items" || reqLine["level"] != "INFO" || reqLine["user"] != "aakash" {
		t.Fatalf("request line: %v", reqLine)
	}
	if strings.Contains(buf.b.String(), "secret") {
		t.Fatal("the query was logged")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic answered %d", rec.Code)
	}
	lines = buf.lines(t)
	if p := lines[len(lines)-2]; p["msg"] != "handler panicked" || p["stack"] == "" || p["trace"] == "" {
		t.Fatalf("panic line: %v", p)
	}
	if l := lines[len(lines)-1]; l["level"] != "ERROR" || l["status"] != float64(500) {
		t.Fatalf("request line after panic: %v", l)
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/missing", nil))
	lines = buf.lines(t)
	if l := lines[len(lines)-1]; l["level"] != "WARN" {
		t.Fatalf("404 line: %v", l)
	}

	before := len(buf.lines(t))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	if got := buf.lines(t); len(got) != before+1 { // just "inside"
		t.Fatalf("healthz logged: %v", got[len(got)-1])
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "bad id\nwith newline")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if id := rec.Header().Get("X-Request-Id"); len(id) != 16 {
		t.Fatalf("bad incoming id kept: %q", id)
	}
}

func TestFailureCause(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelInfo)
	h := Requests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":"database is locked"}`))
		case "/text":
			http.Error(w, "upstream timed out", 502)
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"not logged for 4xx"}`))
		}
	}))
	for _, p := range []string{"/json", "/text", "/bad"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", p, nil))
	}
	lines := buf.lines(t)
	if lines[0]["err"] != "database is locked" || lines[1]["err"] != "upstream timed out" || lines[2]["err"] != nil {
		t.Fatalf("lines: %v", lines)
	}
}

func TestRouteMessage(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelDebug)
	api := http.NewServeMux()
	api.HandleFunc("PUT /api/items/{id}", func(w http.ResponseWriter, _ *http.Request) {})
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	h := Requests(mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/api/items/12", nil))
	if m := buf.lines(t)[0]; m["msg"] != "PUT /api/items/{id}" || m["path"] != "/api/items/12" {
		t.Fatalf("request line: %v", m)
	}
}

func TestSecretPathRedacted(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelDebug)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ping/{token}/{kind}", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("POST /notify/{key}", func(w http.ResponseWriter, _ *http.Request) {})
	h := Requests(mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/ping/s3cr3t-abc/fail", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/notify/k3y", nil))
	lines := buf.lines(t)
	if lines[0]["path"] != "/ping/[redacted]/fail" || lines[1]["path"] != "/notify/[redacted]" {
		t.Fatalf("paths: %v %v", lines[0]["path"], lines[1]["path"])
	}
	if strings.Contains(buf.b.String(), "s3cr3t") || strings.Contains(buf.b.String(), "k3y") {
		t.Fatal("a secret reached the log")
	}
}

func TestJob(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelInfo)
	ctx, run := Job(context.Background(), "mail.sync", "label", "Banks")
	slog.WarnContext(ctx, "one mail skipped")
	run.End(nil, "imported", 3)
	_, run = QuietJob(context.Background(), "check")
	run.End(nil)
	_, run = QuietJob(context.Background(), "check")
	run.End(errors.New("timeout"))

	lines := buf.lines(t)
	if len(lines) != 3 {
		t.Fatalf("lines: %v", lines)
	}
	if lines[0]["trace"] == nil || lines[0]["trace"] != lines[1]["trace"] {
		t.Fatalf("job lines don't share a trace: %v", lines)
	}
	if done := lines[1]; done["msg"] != "mail.sync done" || done["imported"] != float64(3) || done["label"] != "Banks" || done["kind"] != "job" {
		t.Fatalf("done line: %v", done)
	}
	if failed := lines[2]; failed["level"] != "ERROR" || failed["err"] != "timeout" {
		t.Fatalf("failed line: %v", failed)
	}
}

func TestAudit(t *testing.T) {
	buf, _, _ := testLogger(t, slog.LevelInfo)
	Audit(context.Background(), "item.delete", "id", 4)
	if m := buf.lines(t)[0]; m["kind"] != "audit" || m["msg"] != "item.delete" || m["id"] != float64(4) {
		t.Fatalf("audit line: %v", m)
	}
}
