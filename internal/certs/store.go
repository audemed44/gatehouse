// Package certs holds Gatehouse's TLS certificates: PEM files in the data
// folder, picked by SNI, issued and renewed over ACME DNS-01, with a
// warning whenever one gets close to expiring.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Cert is one certificate as shown in the UI and the discovery API. The
// private key never leaves the store.
type Cert struct {
	Name        string    `json:"name"`
	Domains     []string  `json:"domains"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Issuer      string    `json:"issuer"`
	Source      string    `json:"source"` // acme, acme-staging, npm, upload
	LastRenewal time.Time `json:"last_renewal,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
}

func (c Cert) DaysLeft(now time.Time) int {
	return int(c.NotAfter.Sub(now).Hours() / 24)
}

// meta is what's kept next to the PEM files beside the certificate itself.
type meta struct {
	Source      string    `json:"source"`
	LastRenewal time.Time `json:"last_renewal,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
}

type entry struct {
	Cert
	tls *tls.Certificate
}

// Store keeps certificates under dir/<name>/{bundle.pem,meta.json}.
type Store struct {
	dir string
	mu  sync.RWMutex
	all map[string]*entry
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, all: map[string]*entry{}}
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if !it.IsDir() || strings.HasPrefix(it.Name(), ".") {
			continue
		}
		e, err := s.read(it.Name())
		if err != nil {
			// One broken certificate mustn't stop the others being served.
			fmt.Fprintf(os.Stderr, "certificate %s: %v\n", it.Name(), err)
			continue
		}
		s.all[e.Name] = e
	}
	return s, nil
}

func (s *Store) read(name string) (*entry, error) {
	base := filepath.Join(s.dir, name)
	raw, err := os.ReadFile(filepath.Join(base, "bundle.pem"))
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM := ParsePEM(raw)
	e, err := parse(name, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	var m meta
	if raw, err := os.ReadFile(filepath.Join(base, "meta.json")); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	e.Source, e.LastRenewal, e.LastError, e.LastAttempt = m.Source, m.LastRenewal, m.LastError, m.LastAttempt
	return e, nil
}

// parse checks the pair matches and reads the leaf's details.
func parse(name string, certPEM, keyPEM []byte) (*entry, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate and key: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
		pair.Leaf = leaf
	}
	domains := slices.Clone(leaf.DNSNames)
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	for i := range domains {
		domains[i] = strings.ToLower(domains[i])
	}
	issuer := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(leaf.Issuer.Organization[0] + " " + issuer)
	}
	return &entry{
		Cert: Cert{Name: name, Domains: domains, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Issuer: issuer},
		tls:  &pair,
	}, nil
}

// NameFor is the folder a certificate for these domains lives in.
func NameFor(domains []string) string {
	if len(domains) == 0 {
		return "cert"
	}
	return strings.NewReplacer("*", "wildcard", ".", "-", "/", "-").Replace(domains[0])
}

// Put saves a certificate and key, replacing any with the same name. The
// pair is checked before anything is written.
func (s *Store) Put(name string, certPEM, keyPEM []byte, source string) (Cert, error) {
	if !validName(name) {
		return Cert{}, fmt.Errorf("invalid certificate name %q", name)
	}
	e, err := parse(name, certPEM, keyPEM)
	if err != nil {
		return Cert{}, err
	}
	if time.Now().After(e.NotAfter) {
		return Cert{}, errors.New("that certificate has already expired")
	}
	base := filepath.Join(s.dir, name)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return Cert{}, err
	}
	// Chain and key in one file, so a renewal replaces both in one rename
	// and a crash can't leave a certificate next to the wrong key.
	bundle := append(append([]byte{}, certPEM...), keyPEM...)
	if err := writeAtomic(filepath.Join(base, "bundle.pem"), bundle, 0o600); err != nil {
		return Cert{}, err
	}
	e.Source = source
	e.LastRenewal = time.Now()
	s.mu.Lock()
	s.all[name] = e
	s.mu.Unlock()
	s.saveMeta(e)
	return e.Cert, nil
}

func (s *Store) saveMeta(e *entry) {
	raw, _ := json.MarshalIndent(meta{Source: e.Source, LastRenewal: e.LastRenewal, LastError: e.LastError, LastAttempt: e.LastAttempt}, "", "  ")
	_ = writeAtomic(filepath.Join(s.dir, e.Name, "meta.json"), raw, 0o600)
}

// Note records the outcome of a renewal attempt on an existing cert.
func (s *Store) Note(name string, attempt time.Time, errMsg string) {
	s.mu.Lock()
	e, ok := s.all[name]
	if ok {
		e.LastAttempt, e.LastError = attempt, errMsg
	}
	s.mu.Unlock()
	if ok {
		s.saveMeta(e)
	}
}

func (s *Store) Delete(name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid certificate name %q", name)
	}
	s.mu.Lock()
	_, ok := s.all[name]
	delete(s.all, name)
	s.mu.Unlock()
	if !ok {
		return os.ErrNotExist
	}
	return os.RemoveAll(filepath.Join(s.dir, name))
}

func validName(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/\`) && name != "." && name != ".." && !strings.HasPrefix(name, ".")
}

// List returns every certificate, soonest to expire first.
func (s *Store) List() []Cert {
	s.mu.RLock()
	out := make([]Cert, 0, len(s.all))
	for _, e := range s.all {
		c := e.Cert
		c.Domains = slices.Clone(c.Domains)
		out = append(out, c)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out
}

func (s *Store) Get(name string) (Cert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.all[name]
	if !ok {
		return Cert{}, false
	}
	return e.Cert, true
}

// Covers reports whether name matches a certificate domain, wildcards
// covering exactly one label.
func Covers(certDomain, name string) bool {
	if certDomain == name {
		return true
	}
	if rest, ok := strings.CutPrefix(certDomain, "*."); ok {
		if i := strings.IndexByte(name, '.'); i > 0 && name[i+1:] == rest {
			return true
		}
	}
	return false
}

// For returns the certificate to serve for a host name: an unexpired one
// covering it, preferring an exact name, then the latest expiry.
func (s *Store) For(name string) (*tls.Certificate, *Cert) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *entry
	bestExact := false
	for _, e := range s.all {
		exact, covered := false, false
		for _, d := range e.Domains {
			if d == name {
				exact, covered = true, true
				break
			}
			if Covers(d, name) {
				covered = true
			}
		}
		if !covered {
			continue
		}
		expired := now.After(e.NotAfter)
		if best != nil {
			bestExpired := now.After(best.NotAfter)
			switch {
			case expired != bestExpired:
				if expired {
					continue
				}
			case exact != bestExact:
				if !exact {
					continue
				}
			case !e.NotAfter.After(best.NotAfter):
				continue
			}
		}
		best, bestExact = e, exact
	}
	if best == nil {
		return nil, nil
	}
	c := best.Cert
	return best.tls, &c
}

// GetCertificate is for tls.Config: SNI picks the certificate.
func (s *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, errors.New("no server name (SNI) in the TLS handshake")
	}
	c, _ := s.For(hello.ServerName)
	if c == nil {
		return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
	}
	return c, nil
}

// ParsePEM splits an uploaded bundle into certificate chain and key, so a
// single file holding both works as well as two.
func ParsePEM(raw ...[]byte) (certPEM, keyPEM []byte) {
	for _, r := range raw {
		for {
			var b *pem.Block
			b, r = pem.Decode(r)
			if b == nil {
				break
			}
			enc := pem.EncodeToMemory(b)
			if strings.Contains(b.Type, "PRIVATE KEY") {
				keyPEM = append(keyPEM, enc...)
			} else if b.Type == "CERTIFICATE" {
				certPEM = append(certPEM, enc...)
			}
		}
	}
	return certPEM, keyPEM
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Peek reads the domains of the first certificate in a PEM chain.
func Peek(certPEM []byte) ([]string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return nil, errors.New("no certificate in that PEM")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames, nil
	}
	if leaf.Subject.CommonName != "" {
		return []string{leaf.Subject.CommonName}, nil
	}
	return nil, errors.New("the certificate names no domains")
}
