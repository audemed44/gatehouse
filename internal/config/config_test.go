package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func valid() Config {
	c := Config{
		Hosts: []Host{{
			Domains: []string{"Books.Example.com.", "shelfloom.example.com"}, Upstream: "shelfloom:8000",
			Enabled: true, Allow: []string{"100.64.0.0/10", "10.0.0.5"},
		}},
		Redirects: []Redirect{{Domains: []string{"old.example.com"}, Target: "books.example.com", Enabled: true}},
	}
	c.Normalize()
	return c
}

func TestNormalizeAndValidate(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	h := c.Hosts[0]
	if h.Domains[0] != "books.example.com" || h.ID != "books-example-com" {
		t.Fatalf("not normalized: %+v", h)
	}
	if c.Redirects[0].Code != 301 || c.Settings.RenewDays != 30 || c.Settings.WarnDays != 14 {
		t.Fatalf("defaults missing: %+v", c)
	}
	if u, _ := ParseUpstream(h.Upstream); u.String() != "http://shelfloom:8000" {
		t.Fatalf("upstream: %v", u)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(c *Config){
		"already used":      func(c *Config) { c.Redirects[0].Domains = []string{"books.example.com"} },
		"valid domain":      func(c *Config) { c.Hosts[0].Domains = []string{"bad domain"} },
		"http or https":     func(c *Config) { c.Hosts[0].Upstream = "ftp://x:21" },
		"scheme, host":      func(c *Config) { c.Hosts[0].Upstream = "http://x:80/path" },
		"CIDR":              func(c *Config) { c.Hosts[0].Allow = []string{"10.0.0.0/99"} },
		"at least 1m":       func(c *Config) { c.Hosts[0].IdleStop = "5s"; c.Hosts[0].Container = "x" },
		"needs the contain": func(c *Config) { c.Hosts[0].IdleStop = "30m" },
		"301, 302":          func(c *Config) { c.Redirects[0].Code = 200 },
		"no password":       func(c *Config) { c.Hosts[0].BasicAuth = []BasicUser{{User: "me"}} },
		"warn when fewer":   func(c *Config) { c.Settings.WarnDays = 40 },
		"header name":       func(c *Config) { c.Hosts[0].ResponseHeaders = map[string]string{"Bad Header": "x"} },
		"used twice":        func(c *Config) { c.Redirects[0].ID = c.Hosts[0].ID },
	}
	for want, mutate := range cases {
		c := valid().Clone()
		mutate(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

func TestWildcardDomain(t *testing.T) {
	if err := ValidDomain("*.example.com"); err != nil {
		t.Fatal(err)
	}
	if ValidDomain("a.*.example.com") == nil || ValidDomain("-a.example.com") == nil {
		t.Fatal("accepted a bad domain")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gatehouse.json")
	c := valid()
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	c.Hosts[0].Enabled = false
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hosts[0].Enabled || got.Hosts[0].Upstream != "shelfloom:8000" {
		t.Fatalf("round trip: %+v", got.Hosts[0])
	}
	prev, err := Load(path + ".bak")
	if err != nil || !prev.Hosts[0].Enabled {
		t.Fatalf("backup: %+v %v", prev, err)
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	c := valid()
	c.Hosts[0].BasicAuth = []BasicUser{{User: "me", Hash: "$2a$10$x", Password: "plain"}}
	raw, err := ExportYAML(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "plain") {
		t.Fatal("exported a plain password")
	}
	got, err := ParseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hosts[0].BasicAuth[0].Hash != "$2a$10$x" || got.Redirects[0].Target != "books.example.com" {
		t.Fatalf("yaml: %+v", got)
	}
	if _, err := ParseYAML([]byte("hosts: []\nbogus: 1\n")); err == nil {
		t.Fatal("accepted an unknown field")
	}
}
