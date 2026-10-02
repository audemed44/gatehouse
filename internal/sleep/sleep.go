// Package sleep stops containers that haven't had a request for a while
// and starts them again on the next one (scale-to-zero).
//
// Each container goes awake → stopping → sleeping → waking → awake. A
// container is only stopped with no request in flight; long-lived
// connections (WebSockets, uploads, streams) count as in flight until they
// end. The set of containers Gatehouse stopped is saved, so a restart
// still knows they're sleeping rather than down.
package sleep

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/docker"
)

type Docker interface {
	State(ctx context.Context, name string) (docker.State, error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
}

const (
	Awake    = "awake"
	Stopping = "stopping"
	Sleeping = "sleeping"
	Waking   = "waking"
)

// WakeTimeout is how long a container gets to start and accept
// connections.
var WakeTimeout = 3 * time.Minute

// App is one container under scale-to-zero.
type App struct {
	Container string

	idle   atomic.Int64 // nanoseconds
	last   atomic.Int64 // unix nanoseconds of the last request start or end
	active atomic.Int64 // requests in flight

	op sync.Mutex // one start or stop at a time

	mu      sync.Mutex
	probe   string // upstream URL, to tell when it answers
	state   string
	since   time.Time
	err     string
	attempt *Attempt
}

// Attempt is one wake-up; Done is closed when it has finished.
type Attempt struct {
	Done chan struct{}
	Err  error
}

// Begin marks a request in flight; call End when it's finished.
func (a *App) Begin() {
	a.active.Add(1)
	a.last.Store(time.Now().UnixNano())
}

func (a *App) End() {
	a.last.Store(time.Now().UnixNano())
	a.active.Add(-1)
}

// Status is a container's scale-to-zero state for the UI and discovery.
type Status struct {
	Container  string    `json:"container"`
	State      string    `json:"state"`
	Since      time.Time `json:"since"`
	IdleStop   string    `json:"idle_stop"`
	LastActive time.Time `json:"last_active"`
	Active     int64     `json:"active"`
	Error      string    `json:"error,omitempty"`
}

type Manager struct {
	docker Docker
	path   string // saved set of sleeping containers
	now    func() time.Time

	mu   sync.Mutex
	apps map[string]*App
}

// New loads which containers were sleeping. docker may be nil, in which
// case hosts with idle stop just stay awake.
func New(d Docker, path string) *Manager {
	m := &Manager{docker: d, path: path, now: time.Now, apps: map[string]*App{}}
	var sleeping []string
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &sleeping)
	}
	for _, c := range sleeping {
		a := m.newApp(c)
		a.state = Sleeping
	}
	return m
}

func (m *Manager) Enabled() bool { return m.docker != nil }

func (m *Manager) newApp(container string) *App {
	a := &App{Container: container, state: Awake, since: m.now()}
	a.last.Store(m.now().UnixNano())
	m.apps[container] = a
	return a
}

// Configure tracks the containers of hosts with idle stop. A container
// that's no longer configured and was sleeping is started again, so
// turning scale-to-zero off doesn't leave it stopped.
func (m *Manager) Configure(hosts []config.Host) {
	type want struct {
		idle  time.Duration
		probe string
	}
	wanted := map[string]want{}
	for _, h := range hosts {
		if !h.Enabled || h.IdleStop == "" || h.Container == "" {
			continue
		}
		d, _ := time.ParseDuration(h.IdleStop)
		w := wanted[h.Container]
		if d > w.idle { // shared by several hosts: the longest wins
			w.idle = d
		}
		if w.probe == "" {
			if u, err := config.ParseUpstream(h.Upstream); err == nil {
				w.probe = u.String() + "/"
			}
		}
		wanted[h.Container] = w
	}
	m.mu.Lock()
	var dropped []*App
	for name, a := range m.apps {
		if _, ok := wanted[name]; !ok {
			delete(m.apps, name)
			dropped = append(dropped, a)
		}
	}
	for name, w := range wanted {
		a, ok := m.apps[name]
		if !ok {
			a = m.newApp(name)
		}
		a.idle.Store(int64(w.idle))
		a.mu.Lock()
		a.probe = w.probe
		a.mu.Unlock()
	}
	m.mu.Unlock()
	for _, a := range dropped {
		a.mu.Lock()
		asleep := a.state != Awake
		a.mu.Unlock()
		if asleep && m.docker != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := m.docker.Start(ctx, a.Container); err != nil {
					slog.Warn("starting a container no longer under idle stop", "container", a.Container, "err", err)
				}
			}()
		}
	}
	m.save()
}

// Get returns the app for a container, or nil.
func (m *Manager) Get(container string) *App {
	if m.docker == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apps[container]
}

// Ready reports whether requests can go through now. If not, it starts a
// wake-up (unless one is running) and returns it to wait on.
func (m *Manager) Ready(a *App) (bool, *Attempt) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == Awake {
		return true, nil
	}
	if a.attempt == nil {
		a.attempt = &Attempt{Done: make(chan struct{})}
		go m.wake(a, a.attempt)
	}
	return false, a.attempt
}

func (m *Manager) set(a *App, state, errMsg string) {
	a.state, a.since, a.err = state, m.now(), errMsg
}

func (m *Manager) wake(a *App, at *Attempt) {
	a.op.Lock() // waits for a stop in progress
	defer a.op.Unlock()
	a.mu.Lock()
	m.set(a, Waking, "")
	probe := a.probe
	a.mu.Unlock()
	started := m.now()
	slog.Info("waking", "container", a.Container)

	ctx, cancel := context.WithTimeout(context.Background(), WakeTimeout)
	defer cancel()
	err := m.docker.Start(ctx, a.Container)
	if err == nil {
		err = m.waitReady(ctx, a.Container, probe)
	}

	a.mu.Lock()
	if err != nil {
		m.set(a, Sleeping, err.Error())
		slog.Warn("could not wake", "container", a.Container, "err", err)
	} else {
		m.set(a, Awake, "")
		a.last.Store(m.now().UnixNano())
		slog.Info("awake", "container", a.Container, "took", m.now().Sub(started).Round(time.Millisecond))
	}
	at.Err = err
	a.attempt = nil
	a.mu.Unlock()
	close(at.Done)
	m.save()
}

// probeClient asks the upstream for anything at all: any HTTP answer, even
// an error status, means the app is up. A bare TCP connect isn't enough,
// since Docker's port publishing accepts connections before the app does.
var probeClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // only checks it answers
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// waitReady waits until the upstream answers HTTP and a container health
// check, if it has one, has stopped saying "starting".
func (m *Manager) waitReady(ctx context.Context, container, probe string) error {
	for {
		st, err := m.docker.State(ctx, container)
		if err == nil && !st.Running && st.Status != "created" && st.Status != "restarting" {
			return fmt.Errorf("the container is %s", st.Status)
		}
		if err == nil && st.Running && st.Health != "starting" {
			if probe == "" {
				return nil
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
			if resp, err := probeClient.Do(req); err == nil {
				resp.Body.Close()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("it didn't start answering in time")
		case <-time.After(400 * time.Millisecond):
		}
	}
}

// Down is called when the upstream refused a connection: if the container
// isn't running, it's treated as sleeping so the next request wakes it.
func (m *Manager) Down(ctx context.Context, a *App) bool {
	st, err := m.docker.State(ctx, a.Container)
	if err != nil || st.Running {
		return false
	}
	a.mu.Lock()
	if a.state == Awake {
		m.set(a, Sleeping, "")
	}
	a.mu.Unlock()
	m.save()
	return true
}

// Run stops idle containers, checking every 30 seconds.
func (m *Manager) Run(ctx context.Context) {
	if m.docker == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		m.StopIdle(ctx)
	}
}

// StopIdle stops every awake container past its idle time.
func (m *Manager) StopIdle(ctx context.Context) {
	m.mu.Lock()
	apps := make([]*App, 0, len(m.apps))
	for _, a := range m.apps {
		apps = append(apps, a)
	}
	m.mu.Unlock()
	for _, a := range apps {
		if m.idleFor(a) >= time.Duration(a.idle.Load()) {
			if err := m.stop(ctx, a, false); err != nil {
				slog.Warn("could not stop idle container", "container", a.Container, "err", err)
			}
		}
	}
}

func (m *Manager) idleFor(a *App) time.Duration {
	return m.now().Sub(time.Unix(0, a.last.Load()))
}

// Sleep stops a container now if nothing is in flight.
func (m *Manager) Sleep(ctx context.Context, container string) error {
	a := m.Get(container)
	if a == nil {
		return fmt.Errorf("%s isn't under idle stop", container)
	}
	return m.stop(ctx, a, true)
}

// Wake starts a container now.
func (m *Manager) Wake(container string) error {
	a := m.Get(container)
	if a == nil {
		return fmt.Errorf("%s isn't under idle stop", container)
	}
	m.Ready(a)
	return nil
}

func (m *Manager) stop(ctx context.Context, a *App, now bool) error {
	if !a.op.TryLock() {
		return nil // a start or stop is already happening
	}
	defer a.op.Unlock()
	a.mu.Lock()
	if a.state != Awake || a.active.Load() > 0 || (!now && m.idleFor(a) < time.Duration(a.idle.Load())) {
		busy := a.active.Load() > 0
		a.mu.Unlock()
		if now && busy {
			return errors.New("it has requests in flight")
		}
		return nil
	}
	m.set(a, Stopping, "")
	a.mu.Unlock()

	slog.Info("stopping idle container", "container", a.Container, "idle", m.idleFor(a).Round(time.Second))
	err := m.docker.Stop(ctx, a.Container)
	a.mu.Lock()
	if err != nil {
		m.set(a, Awake, "")
		a.last.Store(m.now().UnixNano()) // try again after another idle period
	} else {
		m.set(a, Sleeping, "")
	}
	a.mu.Unlock()
	m.save()
	return err
}

// Statuses lists every container under idle stop.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	apps := make([]*App, 0, len(m.apps))
	for _, a := range m.apps {
		apps = append(apps, a)
	}
	m.mu.Unlock()
	out := make([]Status, 0, len(apps))
	for _, a := range apps {
		out = append(out, m.status(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Container < out[j].Container })
	return out
}

// Status of one container; ok is false if it isn't under idle stop.
func (m *Manager) Status(container string) (Status, bool) {
	a := m.Get(container)
	if a == nil {
		return Status{}, false
	}
	return m.status(a), true
}

func (m *Manager) status(a *App) Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Status{
		Container: a.Container, State: a.state, Since: a.since,
		IdleStop:   time.Duration(a.idle.Load()).String(),
		LastActive: time.Unix(0, a.last.Load()), Active: a.active.Load(), Error: a.err,
	}
}

// save writes which containers are sleeping (or on their way).
func (m *Manager) save() {
	if m.path == "" {
		return
	}
	m.mu.Lock()
	sleeping := []string{}
	for name, a := range m.apps {
		a.mu.Lock()
		if a.state != Awake {
			sleeping = append(sleeping, name)
		}
		a.mu.Unlock()
	}
	m.mu.Unlock()
	sort.Strings(sleeping)
	raw, _ := json.Marshal(sleeping)
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, m.path)
	}
}
