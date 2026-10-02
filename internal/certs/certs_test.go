package certs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audemed44/gatehouse/internal/config"
)

func put(t *testing.T, s *Store, name string, domains []string, notAfter time.Time) {
	t.Helper()
	c, k := SelfSigned(domains, notAfter)
	if _, err := s.Put(name, c, k, "upload"); err != nil {
		t.Fatal(err)
	}
}

func TestStorePicksBySNI(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	put(t, s, "wild", []string{"*.example.com", "example.com"}, time.Now().Add(60*24*time.Hour))
	put(t, s, "books", []string{"books.example.com"}, time.Now().Add(10*24*time.Hour))

	for name, want := range map[string]string{
		"books.example.com": "books", // exact beats wildcard
		"home.example.com":  "wild",
		"example.com":       "wild",
		"a.b.example.com":   "",
		"other.org":         "",
	} {
		_, c := s.For(name)
		got := ""
		if c != nil {
			got = c.Name
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.org"}); err == nil {
		t.Fatal("served a certificate for an unknown name")
	}

	// Reopening reads the same certificates back.
	s2, _ := Open(dir)
	if len(s2.List()) != 2 {
		t.Fatalf("reopened: %+v", s2.List())
	}
	if c, _ := s2.Get("books"); c.Source != "upload" {
		t.Fatalf("meta lost: %+v", c)
	}
}

func TestStoreRejectsBadPairs(t *testing.T) {
	s, _ := Open(t.TempDir())
	c1, _ := SelfSigned([]string{"a.example.com"}, time.Now().Add(time.Hour))
	_, k2 := SelfSigned([]string{"a.example.com"}, time.Now().Add(time.Hour))
	if _, err := s.Put("a", c1, k2, "upload"); err == nil {
		t.Fatal("accepted a key that doesn't match")
	}
	c, k := SelfSigned([]string{"a.example.com"}, time.Now().Add(-time.Minute))
	if _, err := s.Put("a", c, k, "upload"); err == nil {
		t.Fatal("accepted an expired certificate")
	}
	if _, err := s.Put("../x", c1, k2, "upload"); err == nil {
		t.Fatal("accepted a path as a name")
	}
}

func TestParsePEMBundle(t *testing.T) {
	c, k := SelfSigned([]string{"a.example.com"}, time.Now().Add(time.Hour))
	gotC, gotK := ParsePEM(append(append([]byte{}, k...), c...))
	if string(gotC) != string(c) || string(gotK) != string(k) {
		t.Fatal("bundle not split")
	}
}

type fakeIssuer struct {
	mu    sync.Mutex
	calls int
	err   error
	days  int
}

func (f *fakeIssuer) Obtain(_ context.Context, domains []string, _ config.Settings) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, nil, f.err
	}
	c, k := SelfSigned(domains, time.Now().Add(time.Duration(f.days)*24*time.Hour))
	return c, k, nil
}

type notes struct {
	mu  sync.Mutex
	got []map[string]string
	srv *httptest.Server
}

func newNotes(t *testing.T) *notes {
	n := &notes{}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		json.NewDecoder(r.Body).Decode(&m)
		n.mu.Lock()
		n.got = append(n.got, m)
		n.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func TestManagerIssuesRenewsAndWarns(t *testing.T) {
	store, _ := Open(t.TempDir())
	n := newNotes(t)
	settings := config.Default().Settings
	settings.NotifyURL = n.srv.URL
	settings.Certificates = [][]string{{"*.example.com", "example.com"}}
	issuer := &fakeIssuer{days: 90}
	m := NewManager(store, issuer, func() config.Settings { return settings })
	ctx := context.Background()

	// Missing: issued.
	m.Check(ctx)
	if issuer.calls != 1 || len(store.List()) != 1 {
		t.Fatalf("not issued: %d calls, %+v", issuer.calls, store.List())
	}
	st := m.Statuses()
	if len(st) != 1 || !st[0].Managed || st[0].Missing || st[0].DaysLeft < 88 {
		t.Fatalf("status: %+v", st)
	}
	// Fresh: left alone.
	m.Check(ctx)
	if issuer.calls != 1 {
		t.Fatal("renewed a fresh certificate")
	}
	// Due for renewal, and the CA fails: one failure note, an expiry
	// warning (10 days < 14), and no retry straight away.
	m.Now = func() time.Time { return time.Now().Add(80 * 24 * time.Hour) }
	issuer.err = errors.New("dns says no")
	m.Check(ctx)
	m.Check(ctx)
	if issuer.calls != 2 {
		t.Fatalf("retried too soon: %d calls", issuer.calls)
	}
	n.mu.Lock()
	if len(n.got) != 2 || n.got[0]["type"] != "failure" || !strings.Contains(n.got[0]["body"], "dns says no") || n.got[1]["type"] != "warning" {
		t.Fatalf("notifications: %+v", n.got)
	}
	n.mu.Unlock()
	if c, _ := store.Get("wildcard-example-com"); c.LastError != "dns says no" {
		t.Fatalf("error not recorded: %+v", c)
	}
	// After the retry gap, it works again.
	m.Now = func() time.Time { return time.Now().Add(80*24*time.Hour + 7*time.Hour) }
	issuer.err = nil
	m.Check(ctx)
	if issuer.calls != 3 {
		t.Fatalf("didn't retry: %d calls", issuer.calls)
	}
	if c, _ := store.Get("wildcard-example-com"); c.LastError != "" {
		t.Fatalf("error not cleared: %+v", c)
	}
}

func TestManagerWarnsAboutUnmanagedCerts(t *testing.T) {
	store, _ := Open(t.TempDir())
	put(t, store, "old", []string{"old.example.com"}, time.Now().Add(3*24*time.Hour))
	n := newNotes(t)
	settings := config.Default().Settings
	settings.NotifyURL = n.srv.URL
	m := NewManager(store, &fakeIssuer{}, func() config.Settings { return settings })
	m.Check(context.Background())
	m.Check(context.Background())
	if len(n.got) != 1 || !strings.Contains(n.got[0]["title"], "expires in 2 days") {
		t.Fatalf("notifications: %+v", n.got)
	}
}
