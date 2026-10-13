package logging

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

// slowRequest is how long a request may take before it's logged at info
// even when it's a plain read.
const slowRequest = 2 * time.Second

// Requests logs every request once it's answered, gives it a trace (taken
// from an X-Request-Id header when one came in, and sent back in it), and
// turns a panic in a handler into a logged 500.
//
// Levels keep the volume down: failures (5xx) are errors, refusals (4xx)
// warnings, changes (anything but GET/HEAD) and slow requests info, and
// plain reads debug. /healthz isn't logged at all. A failure's line carries
// what the response said went wrong (its "error", or the start of its
// text), so handlers don't each have to log their 500s.
func Requests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace := r.Header.Get("X-Request-Id")
		if !validTrace(trace) {
			trace = newTrace()
		}
		ctx, _ := withScope(r.Context(), trace)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", trace)
		rec := &recorder{ResponseWriter: w}
		start := time.Now()

		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				slog.ErrorContext(ctx, "handler panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				if !rec.wrote {
					http.Error(rec, "internal error", http.StatusInternalServerError)
				}
			}
			if r.URL.Path == "/healthz" {
				return
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			dur := time.Since(start)
			level := slog.LevelDebug
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			case r.Method != http.MethodGet && r.Method != http.MethodHead, dur >= slowRequest:
				level = slog.LevelInfo
			}
			attrs := []slog.Attr{
				slog.String("kind", "request"),
				slog.String("method", r.Method),
				// Never the query, and no secret path segment: either can
				// carry a token.
				slog.String("path", loggedPath(r)),
				slog.Int("status", status),
				slog.Int64("dur_ms", dur.Milliseconds()),
				slog.Int64("bytes", rec.bytes),
				slog.String("ip", clientIP(r)),
			}
			if status >= 500 {
				if msg := rec.failure(); msg != "" {
					attrs = append(attrs, slog.String("err", msg))
				}
			}
			slog.LogAttrs(ctx, level, route(r), attrs...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// route names the request by the pattern that matched it ("PUT
// /api/items/{id}"), so the message stays the same whatever the ids. The
// mux sets r.Pattern on the request it was handed, which is ours.
func route(r *http.Request) string {
	p := r.Pattern
	if p == "" {
		p = r.URL.Path
	}
	if !strings.Contains(p, " ") {
		p = r.Method + " " + p
	}
	return p
}

// secretWildcard matches route wildcards whose value is a secret:
// /ping/{token}, /notify/{key}.
var secretWildcard = regexp.MustCompile(`\{([A-Za-z_]*(?i:token|key|secret|password)[A-Za-z_]*)(?:\.\.\.)?\}`)

// loggedPath is the request's path with the values of secret wildcards
// replaced.
func loggedPath(r *http.Request) string {
	p := r.URL.Path
	for _, m := range secretWildcard.FindAllStringSubmatch(r.Pattern, -1) {
		if v := r.PathValue(m[1]); v != "" {
			p = strings.Replace(p, "/"+v, "/[redacted]", 1)
		}
	}
	return p
}

func validTrace(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// clientIP is the first X-Forwarded-For hop (Gatehouse sets it) or the
// peer address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(ip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recorder notes the status and size of a response. It passes Flush and
// Hijack through, and Unwrap lets http.ResponseController reach the rest.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
	body   []byte // the start of a failure's body
}

// failureBody is how much of a 5xx response is kept for its log line.
const failureBody = 1 << 10

// failure is what a 5xx response said: its JSON "error", or its text,
// with any URL's query and password taken out (Go's HTTP errors quote the
// URL, and widget URLs often carry an API key).
func (r *recorder) failure() string {
	if len(r.body) == 0 {
		return ""
	}
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(r.body))
	if json.Unmarshal(r.body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	return ScrubURLs(msg)
}

var (
	urlQuery    = regexp.MustCompile(`(\b[a-z][a-z0-9+.-]*://[^\s"'?]*)\?[^\s"']*`)
	urlPassword = regexp.MustCompile(`(\b[a-z][a-z0-9+.-]*://[^\s"'/@:]*):[^\s"'/@]*@`)
)

// ScrubURLs replaces the query and the password of every URL in s.
func ScrubURLs(s string) string {
	s = urlQuery.ReplaceAllString(s, "$1?[redacted]")
	return urlPassword.ReplaceAllString(s, "$1:[redacted]@")
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status, r.wrote = http.StatusOK, true
	}
	if r.status >= 500 && len(r.body) < failureBody {
		r.body = append(r.body, b[:min(len(b), failureBody-len(r.body))]...)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		if !r.wrote {
			r.status, r.wrote = http.StatusOK, true
		}
		f.Flush()
	}
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	if !r.wrote {
		r.status, r.wrote = http.StatusSwitchingProtocols, true
	}
	return h.Hijack()
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
