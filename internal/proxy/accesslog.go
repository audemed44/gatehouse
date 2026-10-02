package proxy

import (
	"sort"
	"sync"
	"time"
)

// Entry is one request in the access log. The query string is left out,
// since it can hold tokens.
type Entry struct {
	Time    time.Time `json:"time"`
	Host    string    `json:"host"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Status  int       `json:"status"`
	Bytes   int64     `json:"bytes"`
	Millis  int64     `json:"ms"`
	Client  string    `json:"client"`
	TLS     bool      `json:"tls"`
	Matched bool      `json:"matched"` // false: no host was set up for the name
	// Asleep marks a monitor's probe answered "asleep" (a 503 by design):
	// not an error.
	Asleep bool `json:"asleep,omitempty"`
}

// HostStats counts requests per host since Gatehouse started.
type HostStats struct {
	Host     string    `json:"host"`
	Requests int64     `json:"requests"`
	Status2  int64     `json:"status_2xx"`
	Status3  int64     `json:"status_3xx"`
	Status4  int64     `json:"status_4xx"`
	Status5  int64     `json:"status_5xx"`
	Asleep   int64     `json:"asleep"` // probes answered while the app slept
	Bytes    int64     `json:"bytes"`
	LastSeen time.Time `json:"last_seen"`
}

// AccessLog keeps the most recent requests in a fixed-size ring, so its
// memory use doesn't grow with traffic.
type AccessLog struct {
	mu    sync.Mutex
	ring  []Entry
	next  int
	full  bool
	stats map[string]*HostStats
}

func NewAccessLog(size int) *AccessLog {
	if size <= 0 {
		size = 1000
	}
	return &AccessLog{ring: make([]Entry, size), stats: map[string]*HostStats{}}
}

// Resize keeps the newest entries that fit.
func (l *AccessLog) Resize(size int) {
	if size <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if size == len(l.ring) {
		return
	}
	old := l.ordered()
	if len(old) > size {
		old = old[len(old)-size:]
	}
	l.ring = make([]Entry, size)
	copy(l.ring, old)
	l.next = len(old) % size
	l.full = len(old) == size
}

func (l *AccessLog) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
	key := e.Host
	if !e.Matched {
		key = "" // unknown names share one row, so scanners can't grow the map
	}
	s := l.stats[key]
	if s == nil {
		s = &HostStats{Host: key}
		l.stats[key] = s
	}
	s.Requests++
	s.Bytes += e.Bytes
	s.LastSeen = e.Time
	switch {
	case e.Asleep:
		s.Asleep++
	case e.Status >= 500:
		s.Status5++
	case e.Status >= 400:
		s.Status4++
	case e.Status >= 300:
		s.Status3++
	default:
		s.Status2++
	}
}

// ordered returns entries oldest first; the caller holds the lock.
func (l *AccessLog) ordered() []Entry {
	if !l.full {
		return append([]Entry(nil), l.ring[:l.next]...)
	}
	return append(append([]Entry(nil), l.ring[l.next:]...), l.ring[:l.next]...)
}

// Query returns up to limit entries, newest first, optionally for one
// host and only errors (status 400 and up).
func (l *AccessLog) Query(host string, errorsOnly bool, limit int) []Entry {
	l.mu.Lock()
	all := l.ordered()
	l.mu.Unlock()
	out := []Entry{}
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		e := all[i]
		if host != "" && e.Host != host {
			continue
		}
		if errorsOnly && (e.Status < 400 || e.Asleep) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Stats returns per-host counts, busiest first.
func (l *AccessLog) Stats() []HostStats {
	l.mu.Lock()
	out := make([]HostStats, 0, len(l.stats))
	for _, s := range l.stats {
		out = append(out, *s)
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out
}
