# Gatehouse

Instructions for coding agents working in this repository. `CLAUDE.md`
imports this file.

## Project

A reverse proxy for a homelab, replacing Nginx Proxy Manager. It routes by
host name to upstreams or redirects, gets certificates from Let's Encrypt
over DNS-01 (Cloudflare, via lego), stops idle containers and starts them
on the next request (scale-to-zero), and has an admin UI. A Go server
(`cmd/gatehouse`, `internal/`) serves the proxy on two ports (HTTP, HTTPS)
and the admin JSON API plus the Preact + TypeScript frontend (`frontend/`,
built into `web/dist` and embedded) on a third.

- `internal/config`: the config (hosts, redirects, settings), validation,
  atomic save to `/data/gatehouse.json`, YAML export/import.
- `internal/proxy`: the routing table, swapped atomically on reload; the
  per-host pipeline (HTTPS redirect, allowlist, basic auth, body limit,
  scale-to-zero, `httputil.ReverseProxy`); access log ring; error pages.
- `internal/certs`: PEM bundles in `/data/certs/<name>/`, picked by SNI;
  the renewal manager and expiry warnings; the lego issuer.
- `internal/sleep`: scale-to-zero state per container.
- `internal/docker`: start/stop/inspect over the Docker API.
- `internal/npm`: reads Nginx Proxy Manager's database and certificates.
- `internal/admin`: the admin API, discovery API and Foyer widget.

## Constraints

- **It's the front door: reliability first.** A config change is validated
  and compiled before it's saved and swapped in; a bad one changes nothing.
  In-flight requests finish on the table they started with. Upstream
  transports are shared across reloads so keep-alive connections survive.
  A config file that doesn't validate stops the start rather than serving
  part of it.
- **Low memory is a feature.** It idles around 8 MB. The access log is a
  fixed-size ring; nothing grows with traffic or with unknown host names.
- Direct dependencies: lego (ACME; only the Cloudflare provider is
  compiled in, since importing lego's provider registry pulls in every
  provider), yaml.v3, modernc.org/sqlite (pure Go, only to read NPM's
  database on import) and x/crypto (bcrypt). Justify any new one.
- Secrets: the DNS token stays in the environment, private keys stay in
  `/data/certs` (0600) and never go through the API, basic-auth passwords
  are bcrypt hashes and never returned. The NPM import never reads NPM's
  stored DNS credentials. Notify URLs hold keys, so errors don't echo them.
- The admin API is on its own port and needs the token (bearer or the
  derived session cookie); state-changing browser requests from another
  origin are refused. `/api/discovery` also takes the read-only
  `GATEHOUSE_DISCOVERY_TOKEN`.
- Proxied requests keep the browser's Host header (as NPM does), get
  `X-Forwarded-For/Host/Proto` and `X-Real-IP`, and incoming copies of
  those are dropped. Query strings are never logged.
- UI style is Foyer's: Swiss editorial, always dark, heavy Inter headlines,
  tracked uppercase eyebrows, 2px rules over numbered headings, square
  corners, one accent (#2563ff). Check phone width too.

## Commits

Conventional Commits: `<type>(<scope>): <summary>`, e.g. `feat(proxy): ...`.

## Checks before pushing

```sh
go vet ./... && go test -race ./...        # needs web/dist (npm run build)
cd frontend && npm run format:check && npm run typecheck && npm test && npm run build
docker build -t gatehouse:dev .
```

The ACME path has an integration test against Pebble (Let's Encrypt's test
CA); see `internal/certs/pebble_test.go` for how to run it.
