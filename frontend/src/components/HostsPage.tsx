import { Moon, Plus, Search, Sun } from "lucide-preact";
import { useState } from "preact/hooks";
import { api } from "../api";
import { useData } from "../hooks";
import { ago, certTone, plural, sleepTone } from "../lib";
import type { HostView, Overview, RedirectView } from "../types";
import { HostForm } from "./HostForm";
import { RedirectForm } from "./RedirectForm";
import { Dot, Empty, ErrorNote, Figure, SectionHead, useAction } from "./ui";

export function HostsPage() {
  const hosts = useData(api.hosts, 10_000);
  const redirects = useData(api.redirects);
  const overview = useData(api.overview, 10_000);
  const [editing, setEditing] = useState<HostView | "new" | null>(null);
  const [redirect, setRedirect] = useState<RedirectView | "new" | null>(null);
  const [query, setQuery] = useState("");

  if (!hosts.data || !redirects.data) {
    return hosts.error ? (
      <ErrorNote>{hosts.error}</ErrorNote>
    ) : (
      <div class="skeleton page-skeleton" />
    );
  }
  const q = query.trim().toLowerCase();
  const match = (domains: string[], extra: string) =>
    !q || domains.some((d) => d.includes(q)) || extra.toLowerCase().includes(q);
  const hostRows = hosts.data.filter((h) => match(h.domains, `${h.upstream} ${h.container ?? ""}`));
  const redirectRows = redirects.data.filter((r) => match(r.domains, r.target));
  const reload = () => {
    hosts.reload();
    redirects.reload();
    overview.reload();
  };

  return (
    <div class="page">
      <Head hosts={hosts.data} overview={overview.data} />
      <div class="toolbar">
        <label class="search">
          <Search size={15} />
          <input
            class="input"
            placeholder="Filter by domain, upstream or container"
            value={query}
            onInput={(e) => setQuery(e.currentTarget.value)}
          />
        </label>
        <span class="spacer" />
        <button class="btn btn-ghost" onClick={() => setRedirect("new")}>
          <Plus size={16} /> Redirect
        </button>
        <button class="btn btn-primary" onClick={() => setEditing("new")}>
          <Plus size={16} /> Add host
        </button>
      </div>

      <section class="section">
        <SectionHead index={1} title="Hosts">
          <span class="eyebrow">{plural(hosts.data.length, "host")}</span>
        </SectionHead>
        {hosts.data.length === 0 ? (
          <Empty>
            No hosts yet. Add one, or bring Nginx Proxy Manager's over in{" "}
            <a class="link-btn" href="/settings">
              Settings
            </a>
            .
          </Empty>
        ) : hostRows.length === 0 ? (
          <Empty>Nothing matches.</Empty>
        ) : (
          <div class="host-list">
            <div class="host-row host-header eyebrow" aria-hidden="true">
              <span>Host</span>
              <span>Upstream</span>
              <span class="num">Requests</span>
              <span>TLS · Access</span>
            </div>
            {hostRows.map((h) => (
              <HostLine key={h.id} host={h} onEdit={() => setEditing(h)} onChanged={reload} />
            ))}
          </div>
        )}
      </section>

      <section class="section">
        <SectionHead index={2} title="Redirects">
          <span class="eyebrow">{plural(redirects.data.length, "redirect")}</span>
        </SectionHead>
        {redirectRows.length === 0 ? (
          <Empty>{redirects.data.length ? "Nothing matches." : "No redirects."}</Empty>
        ) : (
          <div class="host-list">
            {redirectRows.map((r) => (
              <button
                key={r.id}
                class={`host-row redirect-row ${r.enabled ? "" : "is-off"}`}
                onClick={() => setRedirect(r)}
              >
                <span class="host-name">
                  <Dot tone={r.enabled ? "accent" : ""} />
                  <span>
                    <span class="host-title">{r.domains[0]}</span>
                    {r.domains.length > 1 && (
                      <span class="host-sub">+{r.domains.slice(1).join(", ")}</span>
                    )}
                  </span>
                </span>
                <span class="host-upstream mono">
                  {r.code} → {r.target}
                  {r.preserve_path ? "/…" : ""}
                </span>
                <span />
                <span class="chips">
                  {!r.enabled && <span class="chip">Off</span>}
                  {r.certificate ? (
                    <span class="chip">HTTPS</span>
                  ) : (
                    <span class="chip chip-warn">No cert</span>
                  )}
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {editing && (
        <HostForm
          host={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reload();
          }}
        />
      )}
      {redirect && (
        <RedirectForm
          redirect={redirect === "new" ? null : redirect}
          onClose={() => setRedirect(null)}
          onSaved={() => {
            setRedirect(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function Head(props: { hosts: HostView[]; overview: Overview | null }) {
  const o = props.overview;
  const enabled = props.hosts.filter((h) => h.enabled).length;
  const certs = (o?.certificates ?? []).filter((c) => !c.missing);
  const soonest = certs.length ? certs.reduce((a, b) => (a.days_left < b.days_left ? a : b)) : null;
  const failing = (o?.certificates ?? []).filter((c) => c.last_error);
  const asleep = (o?.sleep ?? []).filter((s) => s.state !== "awake").length;
  const errors5xx = (o?.stats ?? []).reduce((n, s) => n + (s.host ? s.status_5xx : 0), 0);
  const uncovered = props.hosts.filter((h) => h.enabled && h.uncovered.length > 0);

  return (
    <header class="page-head">
      <div class="eyebrow eyebrow-accent">Front door · {plural(enabled, "host")} serving</div>
      <h1 class="page-title">{enabled === 0 ? "Nothing yet" : "Gatehouse"}</h1>
      <div class="figures">
        <Figure value={enabled} unit={`/${props.hosts.length}`} label="Hosts on" />
        {soonest && (
          <Figure
            value={soonest.days_left}
            unit="d"
            label={`Certificate · ${soonest.name}`}
            tone={certTone(soonest.days_left)}
          />
        )}
        {(o?.sleep.length ?? 0) > 0 && (
          <Figure value={asleep} unit={`/${o!.sleep.length}`} label="Asleep" tone="accent" />
        )}
        <Figure value={errors5xx} label="5xx since start" tone={errors5xx ? "warn" : ""} />
      </div>
      {failing.map((c) => (
        <a key={c.name} class="note note-bad" href="/certificates">
          <strong>{c.name}</strong>: the last renewal failed — {c.last_error}
        </a>
      ))}
      {uncovered.length > 0 && (
        <div class="note note-warn">
          No certificate covers{" "}
          {uncovered
            .flatMap((h) => h.uncovered)
            .slice(0, 6)
            .join(", ")}
          {uncovered.length > 6 ? "…" : ""}: they're served over plain HTTP only.{" "}
          <a class="link-btn" href="/certificates">
            Certificates
          </a>
        </div>
      )}
    </header>
  );
}

function HostLine(props: { host: HostView; onEdit: () => void; onChanged: () => void }) {
  const h = props.host;
  const act = useAction();
  const st = h.stats;
  const sleepAction = async (e: Event, wake: boolean) => {
    e.stopPropagation();
    await act.run(() => (wake ? api.wake(h.id) : api.sleep(h.id)));
    props.onChanged();
  };
  return (
    <div
      class={`host-row ${h.enabled ? "" : "is-off"}`}
      role="button"
      tabIndex={0}
      onClick={props.onEdit}
      onKeyDown={(e) => e.key === "Enter" && props.onEdit()}
    >
      <span class="host-name">
        <Dot tone={!h.enabled ? "" : h.sleep ? sleepTone(h.sleep.state) : "good"} />
        <span>
          <a
            class="host-title"
            href={`https://${h.domains[0]}`}
            target="_blank"
            rel="noreferrer"
            onClick={(e) => e.stopPropagation()}
          >
            {h.domains[0]}
          </a>
          {h.domains.length > 1 && <span class="host-sub">+{h.domains.slice(1).join(", ")}</span>}
        </span>
      </span>
      <span class="host-upstream mono" title={h.upstream}>
        {h.upstream.replace(/^http:\/\//, "")}
      </span>
      <span class="num mono">
        {st ? (
          <a
            class={st.status_5xx ? "tone-bad" : ""}
            href={`/logs?host=${encodeURIComponent(h.domains[0])}`}
            onClick={(e) => e.stopPropagation()}
            title={`${st.status_2xx} 2xx · ${st.status_3xx} 3xx · ${st.status_4xx} 4xx · ${st.status_5xx} 5xx · last ${ago(st.last_seen)}`}
          >
            {st.requests}
            {st.status_5xx ? ` · ${st.status_5xx}×5xx` : ""}
          </a>
        ) : (
          <span class="muted">—</span>
        )}
      </span>
      <span class="chips">
        {!h.enabled && <span class="chip">Off</span>}
        {h.certificate ? (
          <span
            class={`chip ${certTone(h.certificate.days_left) === "good" ? "" : "chip-warn"}`}
            title={`${h.certificate.name}, ${h.certificate.days_left} days left`}
          >
            HTTPS {h.certificate.days_left}d
          </span>
        ) : (
          <span class="chip chip-warn">No cert</span>
        )}
        {h.force_https && <span class="chip">Forced</span>}
        {h.hsts && <span class="chip">HSTS</span>}
        {(h.allow?.length ?? 0) > 0 && (
          <span class="chip" title={h.allow!.join(", ")}>
            Allowlist
          </span>
        )}
        {(h.basic_auth?.length ?? 0) > 0 && <span class="chip">Password</span>}
        {h.sleep && (
          <span class={`chip ${h.sleep.state === "awake" ? "" : "chip-accent"}`}>
            {h.sleep.state === "awake" ? `Idle stop ${h.idle_stop}` : h.sleep.state}
          </span>
        )}
        {h.sleep && h.enabled && (
          <button
            class="icon-btn"
            disabled={act.busy || h.sleep.state === "waking" || h.sleep.state === "stopping"}
            title={h.sleep.state === "awake" ? "Put to sleep now" : "Wake now"}
            aria-label={h.sleep.state === "awake" ? "Put to sleep now" : "Wake now"}
            onClick={(e) => sleepAction(e, h.sleep!.state !== "awake")}
          >
            {h.sleep.state === "awake" ? <Moon size={15} /> : <Sun size={15} />}
          </button>
        )}
      </span>
      {(act.error || h.sleep?.error) && (
        <span class="host-msg">{act.error || `Couldn't wake: ${h.sleep!.error}`}</span>
      )}
    </div>
  );
}
