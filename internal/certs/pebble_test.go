package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/audemed44/gatehouse/internal/config"
)

// TestPebble issues a real certificate over DNS-01 from Pebble, Let's
// Encrypt's test CA. It runs only when one is set up:
//
//	pebble-challtestsrv -management :8055 -dnsserver :8053 -http01 "" -https01 "" -tlsalpn01 "" &
//	PEBBLE_VA_NOSLEEP=1 pebble -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053 &
//	GATEHOUSE_PEBBLE=https://127.0.0.1:14000/dir LEGO_CA_CERTIFICATES=test/certs/pebble.minica.pem go test ./internal/certs -run Pebble
func TestPebble(t *testing.T) {
	dir := os.Getenv("GATEHOUSE_PEBBLE")
	if dir == "" {
		t.Skip("GATEHOUSE_PEBBLE not set")
	}
	l := &Lego{
		Dir: t.TempDir(), CADir: dir, Provider: challtest{"http://127.0.0.1:8055"},
		Options: []dns01.ChallengeOption{dns01.DisableAuthoritativeNssPropagationRequirement()},
	}
	s := config.Default().Settings
	s.ACMEEmail = "" // optional; also checks an account without a contact
	s.Resolvers = []string{"127.0.0.1:8053"}
	store, _ := Open(t.TempDir())
	m := NewManager(store, l, func() config.Settings { return s })
	s.Certificates = [][]string{{"*.example.com", "example.com"}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	m.Check(ctx)
	c, ok := store.Get("wildcard-example-com")
	if !ok || c.LastError != "" || c.Source != "acme" || len(c.Domains) != 2 {
		t.Fatalf("not issued: %+v %v", c, m.Statuses())
	}
	t.Logf("issued by %q until %s", c.Issuer, c.NotAfter)
	// The account is reused for the next one.
	if err := m.issue(ctx, []string{"*.example.com", "example.com"}, true); err != nil {
		t.Fatal(err)
	}
}

// challtest publishes TXT records through pebble-challtestsrv.
type challtest struct{ url string }

func (c challtest) post(path string, body map[string]string) error {
	raw, _ := json.Marshal(body)
	resp, err := http.Post(c.url+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c challtest) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.post("/set-txt", map[string]string{"host": info.EffectiveFQDN, "value": info.Value})
}

func (c challtest) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.post("/clear-txt", map[string]string{"host": info.EffectiveFQDN})
}
