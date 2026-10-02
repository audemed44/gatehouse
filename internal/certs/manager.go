package certs

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/notify"
)

// Issuer gets a certificate for domains from a CA.
type Issuer interface {
	Obtain(ctx context.Context, domains []string, s config.Settings) (certPEM, keyPEM []byte, err error)
}

// retryAfter spaces out failed attempts, so a broken DNS token doesn't
// hammer the CA's rate limits.
const retryAfter = 6 * time.Hour

// warnEvery is how often the same expiry warning repeats.
const warnEvery = 24 * time.Hour

// Manager keeps the certificates listed in the settings issued and
// renewed, and warns about any certificate close to expiry.
type Manager struct {
	Store    *Store
	Issuer   Issuer
	Settings func() config.Settings
	Now      func() time.Time

	issuing sync.Mutex // one issuance at a time
	mu      sync.Mutex
	busy    map[string]bool
	pending map[string]attempt // desired certs not issued yet
	warned  map[string]time.Time
}

type attempt struct {
	at  time.Time
	err string
}

// Status is a certificate as the UI and discovery API show it.
type Status struct {
	Cert
	DaysLeft int  `json:"days_left"`
	Managed  bool `json:"managed"`  // listed in the settings, so renewed
	Renewing bool `json:"renewing"` // an issuance is running
	Missing  bool `json:"missing"`  // listed but not issued yet
}

func NewManager(store *Store, issuer Issuer, settings func() config.Settings) *Manager {
	return &Manager{
		Store: store, Issuer: issuer, Settings: settings, Now: time.Now,
		busy: map[string]bool{}, pending: map[string]attempt{}, warned: map[string]time.Time{},
	}
}

// Run checks shortly after start and then every few hours.
func (m *Manager) Run(ctx context.Context) {
	wait := 20 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		m.Check(ctx)
		wait = 3 * time.Hour
	}
}

// Check issues missing certificates, renews ones due, and sends warnings.
func (m *Manager) Check(ctx context.Context) {
	s := m.Settings()
	now := m.Now()
	for _, domains := range s.Certificates {
		name := NameFor(domains)
		if !m.due(name, domains, s, now) {
			continue
		}
		if err := m.issue(ctx, domains, false); err != nil {
			slog.Warn("certificate", "name", name, "err", err)
		}
	}
	m.warn(ctx, s, now)
}

// due reports whether a desired certificate needs issuing now.
func (m *Manager) due(name string, domains []string, s config.Settings, now time.Time) bool {
	c, ok := m.Store.Get(name)
	last := c.LastAttempt
	failed := c.LastError != ""
	if !ok {
		m.mu.Lock()
		a := m.pending[name]
		m.mu.Unlock()
		last, failed = a.at, a.err != ""
	}
	if failed && now.Sub(last) < retryAfter {
		return false
	}
	if !ok || !sameDomains(c.Domains, domains) {
		return true
	}
	return c.NotAfter.Sub(now) < time.Duration(s.RenewDays)*24*time.Hour
}

func sameDomains(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

// Renew issues a certificate for domains now, in the background. It's an
// error if one is already being issued.
func (m *Manager) Renew(domains []string) error {
	name := NameFor(domains)
	m.mu.Lock()
	busy := m.busy[name]
	m.mu.Unlock()
	if busy {
		return fmt.Errorf("%s is already being issued", name)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if err := m.issue(ctx, domains, true); err != nil {
			slog.Warn("certificate", "name", name, "err", err)
		}
	}()
	return nil
}

func (m *Manager) issue(ctx context.Context, domains []string, manual bool) error {
	name := NameFor(domains)
	m.mu.Lock()
	if m.busy[name] {
		m.mu.Unlock()
		return nil
	}
	m.busy[name] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.busy, name)
		m.mu.Unlock()
	}()

	m.issuing.Lock()
	defer m.issuing.Unlock()
	s := m.Settings()
	started := m.Now()
	slog.Info("requesting a certificate", "domains", domains, "staging", s.ACMEStaging)
	certPEM, keyPEM, err := m.Issuer.Obtain(ctx, domains, s)
	if err == nil {
		source := "acme"
		if s.ACMEStaging {
			source = "acme-staging"
		}
		var c Cert
		if c, err = m.Store.Put(name, certPEM, keyPEM, source); err == nil {
			m.Store.Note(name, started, "")
			m.mu.Lock()
			delete(m.pending, name)
			delete(m.warned, name)
			m.mu.Unlock()
			slog.Info("certificate issued", "name", name, "expires", c.NotAfter.Format(time.DateOnly))
			return nil
		}
	}
	msg := err.Error()
	if _, ok := m.Store.Get(name); ok {
		m.Store.Note(name, started, msg)
	} else {
		m.mu.Lock()
		m.pending[name] = attempt{at: started, err: msg}
		m.mu.Unlock()
	}
	why := "renewal"
	if manual {
		why = "requested renewal"
	}
	if nerr := notify.Send(ctx, s.NotifyURL, "failure", "Gatehouse: certificate "+why+" failed",
		fmt.Sprintf("%s: %s", strings.Join(domains, ", "), msg)); nerr != nil {
		slog.Warn("notify", "err", nerr)
	}
	return err
}

// warn notifies about every certificate within WarnDays of expiry,
// whatever the cause, once a day each.
func (m *Manager) warn(ctx context.Context, s config.Settings, now time.Time) {
	for _, c := range m.Store.List() {
		left := c.NotAfter.Sub(now)
		if left >= time.Duration(s.WarnDays)*24*time.Hour {
			continue
		}
		m.mu.Lock()
		recent := now.Sub(m.warned[c.Name]) < warnEvery
		if !recent {
			m.warned[c.Name] = now
		}
		m.mu.Unlock()
		if recent {
			continue
		}
		title := fmt.Sprintf("Gatehouse: certificate expires in %d days", c.DaysLeft(now))
		if left <= 0 {
			title = "Gatehouse: certificate has expired"
		}
		body := fmt.Sprintf("%s expires %s.", strings.Join(c.Domains, ", "), c.NotAfter.Format("2 Jan 2006 15:04 MST"))
		if c.LastError != "" {
			body += " Last renewal error: " + c.LastError
		}
		slog.Warn("certificate expiring", "name", c.Name, "days", c.DaysLeft(now))
		if err := notify.Send(ctx, s.NotifyURL, "warning", title, body); err != nil {
			slog.Warn("notify", "err", err)
		}
	}
}

// Statuses lists held certificates and desired ones not issued yet.
func (m *Manager) Statuses() []Status {
	s := m.Settings()
	now := m.Now()
	desired := map[string][]string{}
	for _, d := range s.Certificates {
		desired[NameFor(d)] = d
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Status{}
	seen := map[string]bool{}
	for _, c := range m.Store.List() {
		seen[c.Name] = true
		_, managed := desired[c.Name]
		out = append(out, Status{Cert: c, DaysLeft: c.DaysLeft(now), Managed: managed, Renewing: m.busy[c.Name]})
	}
	for name, domains := range desired {
		if seen[name] {
			continue
		}
		a := m.pending[name]
		out = append(out, Status{
			Cert:    Cert{Name: name, Domains: domains, LastError: a.err, LastAttempt: a.at},
			Managed: true, Missing: true, Renewing: m.busy[name],
		})
	}
	return out
}
