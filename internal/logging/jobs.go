package logging

import (
	"context"
	"log/slog"
	"time"
)

// Run is one run of background work (a sync, an import, a backup). Every
// line logged with its context carries the run's trace.
type Run struct {
	ctx   context.Context
	name  string
	args  []any
	start time.Time
	quiet bool
}

// Job starts a run named name ("mail.sync", "ocr.page"): it logs the start
// at debug and returns the context to log with while it runs. args (ids,
// counts, never content) go on the start and end lines.
func Job(ctx context.Context, name string, args ...any) (context.Context, *Run) {
	ctx, _ = withScope(ctx, newTrace())
	r := &Run{ctx: ctx, name: name, args: args, start: time.Now()}
	slog.DebugContext(ctx, name+" started", append([]any{"kind", "job", "job", name}, args...)...)
	return ctx, r
}

// QuietJob is Job for work that runs every minute or so (checks, polls): a
// run that succeeds is logged at debug, so only failures show by default.
func QuietJob(ctx context.Context, name string, args ...any) (context.Context, *Run) {
	ctx, r := Job(ctx, name, args...)
	r.quiet = true
	return ctx, r
}

// End logs how the run went: info (debug when quiet) on success, error
// with err on failure. args add results, like how many things it handled.
func (r *Run) End(err error, args ...any) {
	attrs := append([]any{"kind", "job", "job", r.name, "dur_ms", time.Since(r.start).Milliseconds()}, r.args...)
	attrs = append(attrs, args...)
	if err != nil {
		slog.ErrorContext(r.ctx, r.name+" failed", append(attrs, "err", err.Error())...)
		return
	}
	level := slog.LevelInfo
	if r.quiet {
		level = slog.LevelDebug
	}
	slog.Log(r.ctx, level, r.name+" done", attrs...)
}
