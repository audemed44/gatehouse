// Command gatehouse is a reverse proxy for a homelab: hosts by name,
// certificates over ACME DNS-01, scale-to-zero and an admin UI, from one
// small binary.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // the runtime image may have no zoneinfo; TZ needs this

	"github.com/audemed44/gatehouse/internal/admin"
	"github.com/audemed44/gatehouse/internal/certs"
	"github.com/audemed44/gatehouse/internal/config"
	"github.com/audemed44/gatehouse/internal/docker"
	"github.com/audemed44/gatehouse/internal/proxy"
	"github.com/audemed44/gatehouse/internal/sleep"
	"github.com/audemed44/gatehouse/web"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	level := slog.LevelInfo
	if os.Getenv("GATEHOUSE_DEBUG") != "" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	token := os.Getenv("GATEHOUSE_TOKEN")
	if token == "" {
		fatal("set GATEHOUSE_TOKEN: it's what you sign in to the admin UI with")
	}
	dataDir := env("GATEHOUSE_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fatal("could not create the data folder", "err", err)
	}
	cfgPath := filepath.Join(dataDir, "gatehouse.json")
	cfg, err := loadConfig(cfgPath, filepath.Join(dataDir, "gatehouse.yaml"))
	if err != nil {
		// Refuse to start rather than serve a partial config.
		fatal("the config is invalid; fix it or restore gatehouse.json.bak", "err", err)
	}

	store, err := certs.Open(filepath.Join(dataDir, "certs"))
	if err != nil {
		fatal("could not open the certificate folder", "err", err)
	}
	var dock sleep.Docker
	if host := env("GATEHOUSE_DOCKER_HOST", "/var/run/docker.sock"); strings.HasPrefix(host, "tcp://") || fileExists(strings.TrimPrefix(host, "unix://")) {
		dock = docker.New(host)
	}
	sleeper := sleep.New(dock, filepath.Join(dataDir, "sleeping.json"))
	p := proxy.New(store, sleeper, cfg.Settings.AccessLogSize)
	if err := p.Apply(cfg); err != nil {
		fatal("could not apply the config", "err", err)
	}
	manager := certs.NewManager(store, &certs.Lego{Dir: filepath.Join(dataDir, "acme")},
		func() config.Settings { return p.Config().Settings })

	npmDir := os.Getenv("GATEHOUSE_NPM_DIR")
	if npmDir == "" && fileExists("/npm") {
		npmDir = "/npm"
	}
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err)
	}
	app := admin.New(admin.Options{
		ConfigPath: cfgPath, Proxy: p, Certs: store, Manager: manager, Sleep: sleeper,
		Token: token, DiscoveryToken: os.Getenv("GATEHOUSE_DISCOVERY_TOKEN"), NPMDir: npmDir, Web: dist,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go manager.Run(ctx)
	go sleeper.Run(ctx)
	go reloadOnHUP(ctx, p, cfgPath)

	quiet := log.New(handshakeFilter{}, "", 0)
	servers := []*http.Server{
		{
			Addr: ":" + env("GATEHOUSE_HTTP_PORT", "8080"), Handler: p,
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: quiet,
		},
		{
			Addr: ":" + env("GATEHOUSE_HTTPS_PORT", "8443"), Handler: p,
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: quiet,
			TLSConfig: &tls.Config{GetCertificate: store.GetCertificate, MinVersion: tls.VersionTLS12},
		},
		{
			Addr: ":" + env("GATEHOUSE_ADMIN_PORT", "8081"), Handler: app.Handler(),
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		},
	}
	errs := make(chan error, len(servers))
	for i, srv := range servers {
		go func() {
			var err error
			if i == 1 {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	slog.Info("gatehouse listening", "http", servers[0].Addr, "https", servers[1].Addr, "admin", servers[2].Addr,
		"hosts", len(cfg.Hosts), "certificates", len(store.List()), "docker", dock != nil, "npm", npmDir != "")

	select {
	case <-ctx.Done():
	case err := <-errs:
		slog.Error("server stopped", "err", err)
		defer os.Exit(1)
	}
	// Let requests in flight finish; long-lived ones get 20 seconds.
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
}

// loadConfig reads gatehouse.json; on the very first start, an exported
// gatehouse.yaml next to it is imported instead.
func loadConfig(jsonPath, yamlPath string) (config.Config, error) {
	if !fileExists(jsonPath) && fileExists(yamlPath) {
		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			return config.Config{}, err
		}
		cfg, err := config.ParseYAML(raw)
		if err != nil {
			return config.Config{}, err
		}
		slog.Info("imported gatehouse.yaml")
		return cfg, config.Save(jsonPath, cfg)
	}
	return config.Load(jsonPath)
}

// reloadOnHUP re-reads the config file on SIGHUP, for hand edits. A bad
// file is logged and the running config stays.
func reloadOnHUP(ctx context.Context, p *proxy.Proxy, path string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		cfg, err := config.Load(path)
		if err == nil {
			err = p.Apply(cfg)
		}
		if err != nil {
			slog.Error("reload refused; still serving the previous config", "err", err)
			continue
		}
		slog.Info("config reloaded", "hosts", len(cfg.Hosts))
	}
}

// handshakeFilter keeps TLS handshake noise (scanners, unknown names) at
// debug level.
type handshakeFilter struct{}

func (handshakeFilter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "TLS handshake error") {
		slog.Debug("http", "msg", msg)
	} else {
		slog.Warn("http", "msg", msg)
	}
	return len(p), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func healthcheck() int {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + env("GATEHOUSE_ADMIN_PORT", "8081") + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return 1
	}
	return 0
}
