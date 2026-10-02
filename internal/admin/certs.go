package admin

import (
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
)

type certView struct {
	certs.Status
	Hosts []string `json:"hosts"` // domains served with it
}

func (s *Server) certViews() []certView {
	cfg := s.Proxy.Config()
	var names []string
	for _, h := range cfg.Hosts {
		names = append(names, h.Domains...)
	}
	for _, r := range cfg.Redirects {
		names = append(names, r.Domains...)
	}
	out := []certView{}
	for _, st := range s.Manager.Statuses() {
		v := certView{Status: st, Hosts: []string{}}
		for _, n := range names {
			lookup := n
			if strings.HasPrefix(n, "*.") {
				lookup = "x" + n[1:]
			}
			if _, c := s.Certs.For(lookup); c != nil && c.Name == st.Name {
				v.Hosts = append(v.Hosts, n)
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) listCerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.certViews())
}

// requestCert adds a certificate to the renewal list and issues it now.
func (s *Server) requestCert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domains []string `json:"domains"`
	}
	if !readJSON(w, r, 8<<10, &body) {
		return
	}
	var domains []string
	_, err := s.update(func(c *config.Config) error {
		tmp := config.Config{Settings: config.Settings{Certificates: [][]string{body.Domains}}}
		tmp.Normalize()
		domains = tmp.Settings.Certificates[0]
		if len(domains) == 0 {
			return invalid{errors.New("add at least one domain")}
		}
		name := certs.NameFor(domains)
		c.Settings.Certificates = slices.DeleteFunc(c.Settings.Certificates, func(d []string) bool {
			return certs.NameFor(d) == name // replaces one with the same first domain
		})
		c.Settings.Certificates = append(c.Settings.Certificates, domains)
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.Manager.Renew(domains); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"name": certs.NameFor(domains)})
}

func (s *Server) renewCert(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, d := range s.Proxy.Config().Settings.Certificates {
		if certs.NameFor(d) == name {
			if err := s.Manager.Renew(d); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	if _, ok := s.Certs.Get(name); ok {
		writeError(w, http.StatusConflict, "this certificate isn't renewed by Gatehouse; request one for the same domains to take it over")
		return
	}
	fail(w, errNotFound)
}

// deleteCert removes a certificate and stops renewing it.
func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, held := s.Certs.Get(name)
	managed := slices.ContainsFunc(s.Proxy.Config().Settings.Certificates, func(d []string) bool { return certs.NameFor(d) == name })
	if !held && !managed {
		fail(w, errNotFound)
		return
	}
	if managed {
		if _, err := s.update(func(c *config.Config) error {
			c.Settings.Certificates = slices.DeleteFunc(c.Settings.Certificates, func(d []string) bool { return certs.NameFor(d) == name })
			return nil
		}); err != nil {
			fail(w, err)
			return
		}
	}
	if held {
		if err := s.Certs.Delete(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// uploadCert takes a certificate and key as form files ("cert", "key") or
// one file holding both, for certificates from elsewhere.
func (s *Server) uploadCert(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "upload the certificate and key as files")
		return
	}
	var parts [][]byte
	for _, field := range []string{"cert", "key"} {
		f, _, err := r.FormFile(field)
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		parts = append(parts, raw)
	}
	if v := r.FormValue("pem"); v != "" {
		parts = append(parts, []byte(v))
	}
	certPEM, keyPEM := certs.ParsePEM(parts...)
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "need both a certificate and its private key in PEM format")
		return
	}
	probe, err := certs.Peek(certPEM)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	name := certs.NameFor(probe)
	if c, ok := s.Certs.Get(name); ok && c.Source != "upload" {
		name += "-upload"
	}
	c, err := s.Certs.Put(name, certPEM, keyPEM, "upload")
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}
