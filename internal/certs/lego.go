package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	"github.com/audemed44/gatehouse/internal/config"
)

// Lego issues certificates from Let's Encrypt with DNS-01, so it works for
// a server nothing on the internet can reach. The provider reads its API
// token from the environment (CF_DNS_API_TOKEN for Cloudflare); it never
// goes in the config or the API.
type Lego struct {
	Dir string // ACME account keys

	// CADir overrides Let's Encrypt (tests point it at Pebble).
	CADir string
	// Provider overrides the DNS provider (tests).
	Provider challenge.Provider
	// Options are extra DNS-01 options (tests skip propagation checks).
	Options []dns01.ChallengeOption

	mu sync.Mutex
}

type account struct {
	Email        string                 `json:"email"`
	Key          string                 `json:"key"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// Providers Gatehouse can use for DNS-01. Each one is compiled in, so only
// the ones in use are listed rather than all of lego's.
var Providers = []string{"cloudflare"}

func dnsProvider(name string) (challenge.Provider, error) {
	switch name {
	case "cloudflare":
		p, err := cloudflare.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("cloudflare: set CF_DNS_API_TOKEN to a token with Zone:DNS:Edit (%v)", err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown DNS provider %q (have %s)", name, strings.Join(Providers, ", "))
}

func (l *Lego) Obtain(ctx context.Context, domains []string, s config.Settings) ([]byte, []byte, error) {
	caDir := l.CADir
	env := "staging"
	if caDir == "" {
		caDir = lego.LEDirectoryProduction
		env = "production"
		if s.ACMEStaging {
			caDir = lego.LEDirectoryStaging
			env = "staging"
		}
	}
	provider := l.Provider
	if provider == nil {
		var err error
		if provider, err = dnsProvider(s.DNSProvider); err != nil {
			return nil, nil, err
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	acct, err := l.account(s.ACMEEmail, env)
	if err != nil {
		return nil, nil, err
	}
	cfg := lego.NewConfig(acct)
	cfg.CADirURL = caDir
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ACME: %w", err)
	}
	opts := append([]dns01.ChallengeOption{dns01.AddRecursiveNameservers(s.Resolvers)}, l.Options...)
	if err := client.Challenge.SetDNS01Provider(provider, opts...); err != nil {
		return nil, nil, err
	}
	if acct.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("ACME registration: %w", err)
		}
		acct.Registration = reg
		if err := l.saveAccount(acct, env); err != nil {
			return nil, nil, err
		}
	}

	type result struct {
		res *certificate.Resource
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
		done <- result{res, err}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case r := <-done:
		if r.err != nil {
			return nil, nil, r.err
		}
		return r.res.Certificate, r.res.PrivateKey, nil
	}
}

func (l *Lego) accountPath(env string) string {
	return filepath.Join(l.Dir, "account-"+env+".json")
}

// account loads the ACME account for this environment, or makes a new key.
// A changed email starts a new account.
func (l *Lego) account(email, env string) (*account, error) {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return nil, err
	}
	var a account
	if raw, err := os.ReadFile(l.accountPath(env)); err == nil {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("ACME account: %w", err)
		}
		if block, _ := pem.Decode([]byte(a.Key)); block != nil {
			a.key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("ACME account key: %w", err)
			}
		}
	}
	if a.key == nil || a.Email != email {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, _ := x509.MarshalECPrivateKey(key)
		a = account{Email: email, key: key, Key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))}
	}
	return &a, nil
}

func (l *Lego) saveAccount(a *account, env string) error {
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(l.accountPath(env), raw, 0o600)
}
