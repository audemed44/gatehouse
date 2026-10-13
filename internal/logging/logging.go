// Package logging sets up the app's logs: one JSON object per line on
// stderr, which Logbook (audemed44/logbook) collects from the container.
//
// Field names Logbook understands, beyond time/level/msg:
//
//	app     the app's name, on every line
//	kind    "request", "job" or "audit"; plain lines have none
//	trace   ties together every line of one request or one job run
//	user    who made the request, when the app knows
//	err     the error, on failures
//	dur_ms  how long a request or job took
//
// Log with the Context variants (slog.InfoContext, ...) inside requests and
// jobs so their lines carry the trace. Never log secrets, tokens, or the
// content of what the app stores; keys that look like secrets are redacted
// anyway (see redact).
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
)

// Setup makes a logger for app the default, configured from the
// environment:
//
//	LOG_LEVEL   debug, info (default), warn or error
//	LOG_FORMAT  json (default) or text, for reading in a terminal
func Setup(app string, w io.Writer) *slog.Logger {
	l, lim := build(app, w, ParseLevel(os.Getenv("LOG_LEVEL")), strings.EqualFold(os.Getenv("LOG_FORMAT"), "text"))
	go lim.run(context.Background())
	slog.SetDefault(l)
	return l
}

// build makes the handler chain: trace and user from the context, then the
// rate limits, then redaction and truncation as each line is encoded.
func build(app string, w io.Writer, level slog.Level, text bool) (*slog.Logger, *limiter) {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		return truncate(redact(groups, a))
	}}
	var h slog.Handler
	if text {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	lim := newLimiter(h, app)
	return slog.New(contextHandler{limitHandler{h, lim}}).With("app", app), lim
}

// ParseLevel reads a LOG_LEVEL value; anything unknown is info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// ServerErrorLog is for http.Server.ErrorLog, so the server's own
// complaints (bad TLS handshakes, panics it caught) are JSON lines too.
func ServerErrorLog() *log.Logger {
	return slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)
}

// secretWords mark attribute keys whose values are never written.
var secretWords = []string{"token", "password", "passwd", "secret", "authorization", "cookie", "apikey", "api_key", "credential", "private_key"}

func redact(_ []string, a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, w := range secretWords {
		if strings.Contains(k, w) {
			return slog.String(a.Key, "[redacted]")
		}
	}
	return a
}

// scope is what a request or job run adds to every line logged with its
// context. user is set after authentication, so it's a pointer that the
// auth code fills in (SetUser).
type scope struct {
	trace string
	user  string
}

type scopeKey struct{}

func scopeFrom(ctx context.Context) *scope {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(scopeKey{}).(*scope)
	return s
}

func withScope(ctx context.Context, trace string) (context.Context, *scope) {
	s := &scope{trace: trace}
	if parent := scopeFrom(ctx); parent != nil {
		s.user = parent.user
	}
	return context.WithValue(ctx, scopeKey{}, s), s
}

// Trace is the trace id carried by ctx, or "".
func Trace(ctx context.Context) string {
	if s := scopeFrom(ctx); s != nil {
		return s.trace
	}
	return ""
}

// SetUser records who is behind the request, for every later line logged
// with its context (and the request line itself).
func SetUser(ctx context.Context, user string) {
	if s := scopeFrom(ctx); s != nil {
		s.user = user
	}
}

func newTrace() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// contextHandler adds trace and user from the context to each record.
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if s := scopeFrom(ctx); s != nil {
		if s.trace != "" {
			r.AddAttrs(slog.String("trace", s.trace))
		}
		if s.user != "" {
			r.AddAttrs(slog.String("user", s.user))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

// Audit records something a person did: signed in, changed a setting,
// deleted a thing. action is short and stable, like "item.delete", so
// Logbook can filter on it; args add the details (ids, names, never the
// content).
func Audit(ctx context.Context, action string, args ...any) {
	slog.InfoContext(ctx, action, append([]any{"kind", "audit"}, args...)...)
}
