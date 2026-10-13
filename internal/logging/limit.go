package logging

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Limits keep a failing app from flooding the logs: a loop that fails the
// same way every few milliseconds writes a few lines a minute plus a count,
// not gigabytes.
const (
	// perMessage is how many lines with the same level and message may be
	// written in one window; the rest are counted and summed up once the
	// window ends.
	perMessage = 20
	// perWindow caps all lines in one window, whatever they say.
	perWindow = 600
	window    = time.Minute
	// maxValue is the longest string value written; stack traces get more.
	maxValue = 4 << 10
	maxStack = 16 << 10
	// maxKeys bounds the per-message counts kept in memory in one window.
	maxKeys = 1000
)

// limiter is shared by every handler derived from the one Setup makes.
type limiter struct {
	mu      sync.Mutex
	out     slog.Handler // where the summaries go: no app attrs, see flush
	app     string
	start   time.Time
	total   int
	counts  map[string]*count
	dropped int // over perWindow (or maxKeys) and not counted per message
	now     func() time.Time
}

type count struct {
	level   slog.Level
	msg     string
	n       int
	dropped int
}

func newLimiter(out slog.Handler, app string) *limiter {
	return &limiter{out: out, app: app, counts: map[string]*count{}, now: time.Now}
}

// allow says whether a record may be written, rolling the window over (and
// writing what the last one dropped) when it has ended.
func (l *limiter) allow(level slog.Level, msg string) bool {
	l.mu.Lock()
	now := l.now()
	var summary []slog.Record
	if now.Sub(l.start) >= window {
		summary = l.rollover(now)
	}
	ok := l.take(level, msg)
	l.mu.Unlock()
	l.write(summary)
	return ok
}

func (l *limiter) take(level slog.Level, msg string) bool {
	key := level.String() + "\x00" + msg
	c := l.counts[key]
	if c == nil {
		if len(l.counts) >= maxKeys {
			l.dropped++
			return false
		}
		c = &count{level: level, msg: msg}
		l.counts[key] = c
	}
	if c.n >= perMessage || l.total >= perWindow {
		c.dropped++
		return false
	}
	c.n++
	l.total++
	return true
}

// rollover starts a new window and returns the summary lines for the old
// one. Call it with mu held.
func (l *limiter) rollover(now time.Time) []slog.Record {
	var out []slog.Record
	for _, c := range l.counts {
		if c.dropped == 0 {
			continue
		}
		r := slog.NewRecord(now, c.level, "suppressed repeats of: "+c.msg, 0)
		r.AddAttrs(slog.String("app", l.app), slog.String("kind", "suppressed"),
			slog.Int("suppressed", c.dropped), slog.String("of", c.msg))
		out = append(out, r)
	}
	if l.dropped > 0 {
		r := slog.NewRecord(now, slog.LevelWarn, "suppressed log lines: too many different messages", 0)
		r.AddAttrs(slog.String("app", l.app), slog.String("kind", "suppressed"), slog.Int("suppressed", l.dropped))
		out = append(out, r)
	}
	l.start, l.total, l.dropped = now, 0, 0
	clear(l.counts)
	return out
}

func (l *limiter) write(rs []slog.Record) {
	for _, r := range rs {
		_ = l.out.Handle(context.Background(), r)
	}
}

// run writes the summaries for windows that end quietly too, until ctx is
// done.
func (l *limiter) run(ctx context.Context) {
	t := time.NewTicker(window / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			var summary []slog.Record
			if now := l.now(); now.Sub(l.start) >= window {
				summary = l.rollover(now)
			}
			l.mu.Unlock()
			l.write(summary)
		}
	}
}

// limitHandler drops what the limiter refuses.
type limitHandler struct {
	slog.Handler
	l *limiter
}

func (h limitHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.l.allow(r.Level, r.Message) {
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

func (h limitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return limitHandler{h.Handler.WithAttrs(attrs), h.l}
}

func (h limitHandler) WithGroup(name string) slog.Handler {
	return limitHandler{h.Handler.WithGroup(name), h.l}
}

// truncate shortens long string values (messages included), so one huge
// error body can't make a megabyte line.
func truncate(a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindString {
		return a
	}
	limit := maxValue
	if a.Key == "stack" {
		limit = maxStack
	}
	s := a.Value.String()
	if len(s) <= limit {
		return a
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	var b strings.Builder
	b.WriteString(s[:cut])
	b.WriteString("… [truncated]")
	return slog.String(a.Key, b.String())
}
