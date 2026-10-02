package proxy

import (
	"html/template"
	"net/http"
)

// The proxy's own pages: unknown host, refused, upstream down, waking up.
// Dark, plain, no external assets.
var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">{{end}}
<title>{{.Title}}</title>
<style>
html{background:#000;color:#e8e8e8;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
main{max-width:520px;width:100%;border-top:2px solid #e8e8e8;padding-top:18px}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#2563ff;font-weight:600}
h1{font-size:40px;line-height:1.05;margin:10px 0 12px;font-weight:800;letter-spacing:-.02em}
p{color:#9a9a9a;margin:0}
.code{font:13px ui-monospace,monospace;color:#6b6b6b;margin-top:22px}
.bar{height:2px;background:#1a1a1a;margin-top:22px;overflow:hidden}
.bar i{display:block;height:100%;width:30%;background:#2563ff;animation:s 1.2s ease-in-out infinite}
@keyframes s{0%{transform:translateX(-100%)}100%{transform:translateX(340%)}}
@media (prefers-reduced-motion:reduce){.bar i{animation:none;width:100%}}
</style></head>
<body><main>
<div class="eyebrow">Gatehouse</div>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
{{if .Refresh}}<div class="bar" role="progressbar" aria-label="Starting"><i></i></div>{{end}}
<div class="code">{{.Code}}</div>
</main></body></html>
`))

type pageData struct {
	Title, Message string
	Code           int
	Refresh        int
}

func page(w http.ResponseWriter, code int, title, msg string) {
	render(w, pageData{Title: title, Message: msg, Code: code}, code)
}

func wakingPage(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "2")
	render(w, pageData{
		Title: "Waking up", Message: "This service was asleep to save memory. It's starting and this page will reload when it's ready.",
		Code: http.StatusServiceUnavailable, Refresh: 2,
	}, http.StatusServiceUnavailable)
}

func render(w http.ResponseWriter, d pageData, code int) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = pageTmpl.Execute(w, d)
}
