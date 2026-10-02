// Package admin is Gatehouse's admin API and UI, on its own port, apart
// from the proxy listeners. Every /api/ call needs the admin token, except
// the read-only discovery API, which also takes the discovery token.
package admin

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/proxy"
	"github.com/audemed44/gatehouse/internal/sleep"
)

type Options struct {
	ConfigPath     string
	Proxy          *proxy.Proxy
	Certs          *certs.Store
	Manager        *certs.Manager
	Sleep          *sleep.Manager
	Token          string
	DiscoveryToken string // optional read-only token for /api/discovery
	NPMDir         string // where NPM's folder is mounted, for the import
	Web            fs.FS
}

type Server struct {
	Options
	session string
	mu      sync.Mutex // one config change at a time
}

func New(o Options) *Server {
	return &Server{Options: o, session: sessionValue(o.Token)}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/overview", s.overview)

	api.HandleFunc("GET /api/hosts", s.listHosts)
	api.HandleFunc("POST /api/hosts", s.saveHost)
	api.HandleFunc("PUT /api/hosts/{id}", s.saveHost)
	api.HandleFunc("DELETE /api/hosts/{id}", s.deleteHost)
	api.HandleFunc("POST /api/hosts/test", s.testHost)
	api.HandleFunc("POST /api/hosts/{id}/wake", s.wakeHost)
	api.HandleFunc("POST /api/hosts/{id}/sleep", s.sleepHost)

	api.HandleFunc("GET /api/redirects", s.listRedirects)
	api.HandleFunc("POST /api/redirects", s.saveRedirect)
	api.HandleFunc("PUT /api/redirects/{id}", s.saveRedirect)
	api.HandleFunc("DELETE /api/redirects/{id}", s.deleteRedirect)

	api.HandleFunc("GET /api/certificates", s.listCerts)
	api.HandleFunc("POST /api/certificates", s.requestCert)
	api.HandleFunc("POST /api/certificates/upload", s.uploadCert)
	api.HandleFunc("POST /api/certificates/{name}/renew", s.renewCert)
	api.HandleFunc("DELETE /api/certificates/{name}", s.deleteCert)

	api.HandleFunc("GET /api/logs", s.logs)

	api.HandleFunc("GET /api/settings", s.getSettings)
	api.HandleFunc("PUT /api/settings", s.putSettings)
	api.HandleFunc("GET /api/npm", s.previewNPM)
	api.HandleFunc("POST /api/npm", s.importNPM)
	api.HandleFunc("GET /api/config", s.exportConfig)
	api.HandleFunc("POST /api/config", s.importConfig)

	api.HandleFunc("GET /api/foyer/widget", s.foyerWidget)
	api.HandleFunc("POST /api/foyer/wake/{container}", s.foyerWake)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", s.getSession)
	mux.HandleFunc("POST /api/session", s.login)
	mux.HandleFunc("DELETE /api/session", s.logout)
	mux.Handle("GET /api/discovery", s.requireDiscovery(http.HandlerFunc(s.discovery)))
	mux.Handle("/api/", s.requireAuth(api))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", s.spa())
	return securityHeaders(sameOrigin(mux))
}

// invalid is a config the user got wrong, as opposed to a server failure.
type invalid struct{ error }

// update applies a change to a copy of the config, checks it compiles,
// saves it, then swaps it in. Any failure leaves the running config alone.
func (s *Server) update(fn func(c *config.Config) error) (config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Proxy.Config().Clone()
	if err := fn(&c); err != nil {
		return config.Config{}, err
	}
	c.Normalize()
	if err := s.Proxy.Check(c); err != nil {
		return config.Config{}, invalid{err}
	}
	if err := config.Save(s.ConfigPath, c); err != nil {
		return config.Config{}, err
	}
	if err := s.Proxy.Apply(c); err != nil {
		return config.Config{}, invalid{err}
	}
	return c, nil
}

var errNotFound = errors.New("not found")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("write response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail answers 422 for config mistakes, 404 for missing things, else 500.
func fail(w http.ResponseWriter, err error) {
	var bad invalid
	switch {
	case errors.As(err, &bad):
		writeError(w, http.StatusUnprocessableEntity, bad.Error())
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not found")
	default:
		slog.Error("request failed", "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "expected JSON")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

// spa serves the built frontend, falling back to index.html for app routes.
func (s *Server) spa() http.Handler {
	files := http.FileServer(http.FS(s.Web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" {
			if info, err := fs.Stat(s.Web, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(s.Web, "index.html")
		if err != nil {
			http.Error(w, "frontend not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
