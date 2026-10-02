# Gatehouse

A reverse proxy for a homelab, with a web UI. It replaces Nginx Proxy Manager
(Node, nginx and certbot, ~217 MB) with one Go binary that idles at about
**8 MB**.

- **Hosts by name:** one or more domains per host, sent to `container:port`
  or `host:port`, over HTTP or HTTPS. Wildcard domains (`*.example.com`)
  work too. WebSockets, HTTP/2, streaming responses and large uploads all
  pass through.
- **Per-host options:** redirect HTTP to HTTPS, HSTS, request and response
  headers, an IP allowlist (e.g. only the tailnet), basic auth, an upload
  size limit and a response timeout.
- **Redirect hosts**, plus a plain 404 page for names nothing is set up for.
- **Certificates from Let's Encrypt over DNS-01** (Cloudflare), so the
  server doesn't need to be reachable from the internet. Wildcards are
  supported. Certificates are renewed with 30 days left, and **any**
  certificate below 14 days gets a warning sent to Lookout (or any
  Apprise-style endpoint), whatever the cause. You can also upload
  certificates from elsewhere.
- **Scale-to-zero:** a host can stop its container after it has been idle
  for a while (e.g. `30m`). The next request starts it again: browsers see a
  "waking up" page that reloads itself, while API clients simply wait. Open
  WebSockets and uploads count as activity.
- **Hot reload:** a change is validated whole before it applies. A bad one
  is rejected and the running config keeps serving; in-flight requests are
  never dropped.
- **Admin UI and API** on a separate port: hosts with a live test (does the
  upstream answer, does the name resolve, is there a certificate),
  certificates, the access log, settings, and YAML export/import.
- **Import from Nginx Proxy Manager**: proxy hosts, redirects and
  certificates are read from NPM's folder, mounted read-only.
- **Discovery API** for Foyer and Lookout, and a Foyer widget.

## Run it

See [`docker-compose.example.yml`](docker-compose.example.yml). The image
listens on 8080 (HTTP), 8443 (HTTPS) and 8081 (admin), so it runs as an
unprivileged user; map 80 and 443 to the first two.

| Variable | |
|---|---|
| `GATEHOUSE_TOKEN` | Required. Signs you in to the admin UI and API. |
| `GATEHOUSE_DISCOVERY_TOKEN` | Optional read-only token for `/api/discovery`. |
| `CF_DNS_API_TOKEN` | A Cloudflare API token with Zone · DNS · Edit, used to issue and renew certificates. |
| `GATEHOUSE_NPM_DIR` | Where NPM's folder is mounted, for the import (default `/npm` if it exists). |
| `GATEHOUSE_DOCKER_HOST` | The Docker API, for scale-to-zero: a socket path (default `/var/run/docker.sock`) or `tcp://socket-proxy:2375`. |
| `GATEHOUSE_HTTP_PORT`, `GATEHOUSE_HTTPS_PORT`, `GATEHOUSE_ADMIN_PORT` | Default to 8080, 8443 and 8081. |

Everything lives in `/data`:
- `gatehouse.json` is the config (the previous version is kept as `.bak`).
- `certs/<name>/bundle.pem` holds each certificate chain with its key.
- `acme/` holds the Let's Encrypt account.
- `sleeping.json` records which containers Gatehouse stopped.

If there's no config yet, an exported `gatehouse.yaml` in `/data` is loaded
on the first start. After editing `gatehouse.json` by hand, send `SIGHUP`
to reload it.

To reach the admin UI through the proxy as well as on its own port, add a
host such as `gatehouse.example.com → http://127.0.0.1:8081` with an
allowlist. The direct port keeps working if that host is ever broken.

## Moving from Nginx Proxy Manager

1. **Run it alongside NPM** on spare ports (e.g. `8090:8080` and
   `8453:8443`), with NPM's folder mounted read-only at `/npm`.
2. In **Settings → Import from Nginx Proxy Manager**, click **Preview**,
   then **Import**. Proxy hosts, redirects and the Let's Encrypt
   certificate are copied over, and the certificate goes on the renewal
   list. NPM's stored DNS credentials are never read: set
   `CF_DNS_API_TOKEN` yourself. Custom nginx config, locations, access
   lists and streams are listed rather than imported.
3. **Check every host** through the spare ports, e.g.
   `curl --resolve books.example.com:8453:<server> https://books.example.com:8453/`.
4. **Cut over:** stop NPM (don't delete it), then move 80 and 443 to
   Gatehouse.
5. **To roll back,** stop Gatehouse and start NPM again. Its config and
   certificates are untouched. Remove NPM once things have been quiet for
   a while.

## Scale-to-zero

Set **Stop after idle** and the container on a host. Gatehouse checks every
30 seconds and stops a container that has had no requests for that long and
has none in flight. On the next request it starts the container and waits
until it answers HTTP, and until its health check, if it has one, is no
longer "starting".

If the container was stopped by something else, the first refused
connection is noticed and the request wakes it too. Turning idle stop off
for a host starts its container again.

Other tools should treat a sleeping container as asleep, not down. The
discovery API reports each host's `state` (`awake`, `stopping`, `sleeping`
or `waking`) for that.

Monitors should send an `X-Gatehouse-Probe: 1` header, as Lookout does. A
request with it never wakes an app and doesn't count as activity. A sleeping
app answers it with a 503 and `X-Gatehouse-State: sleeping`, so the monitor
can show the app as asleep rather than down. Without the header, an
every-minute check would keep an app from ever going to sleep.

Gatehouse only needs three Docker API calls: start, stop and inspect. To
give it no more than that, put a socket proxy in front and set
`GATEHOUSE_DOCKER_HOST`.

## Discovery API

`GET /api/discovery` on the admin port. Pass the discovery token (or the
admin token) as a bearer token.

```json
{
  "hosts": [{
    "id": "books-example-com", "domains": ["books.example.com"],
    "upstream": "http://shelfloom:8000", "scheme": "http",
    "forward_host": "shelfloom", "forward_port": 8000, "enabled": true,
    "https": true, "certificate": "wildcard-example-com",
    "cert_expires": "2026-11-27T19:37:21Z",
    "container": "", "idle_stop": "", "state": "awake"
  }],
  "redirects": [{ "id": "…", "domains": ["…"], "target": "…", "code": 301, "enabled": true }],
  "certificates": [{
    "name": "wildcard-example-com", "domains": ["*.example.com", "example.com"],
    "issuer": "Let's Encrypt E7", "source": "acme", "expires": "…",
    "days": 56, "hosts": 20, "managed": true
  }],
  "warn_days": 14,
  "generated": "…"
}
```

`GET /api/foyer/widget` serves a card in
[Foyer's app widget format](https://github.com/audemed44/foyer/blob/main/docs/app-widgets.md),
with hosts, the soonest certificate expiry, 5xx counts, and a **Wake**
button for each sleeping app.

## Development

```sh
cd frontend && npm ci && npm run build && cd ..
GATEHOUSE_TOKEN=dev GATEHOUSE_DATA_DIR=./tmp GATEHOUSE_HTTP_PORT=18080 \
  GATEHOUSE_HTTPS_PORT=18443 go run ./cmd/gatehouse
cd frontend && npm run dev   # proxies /api to :8081 (GATEHOUSE_URL)
```

The checks CI runs are listed in [AGENTS.md](AGENTS.md).
