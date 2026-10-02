import { Download, Upload } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import { api } from "../api";
import { useData, useUnsavedWarning } from "../hooks";
import { plural, splitList } from "../lib";
import type { NPMFound, NPMReport, Settings, SettingsView } from "../types";
import { CopyField, ErrorNote, Field, SectionHead, useAction } from "./ui";

export function SettingsPage() {
  const { data, error, setData } = useData(api.settings);
  if (!data) return error ? <ErrorNote>{error}</ErrorNote> : <div class="skeleton page-skeleton" />;
  return (
    <div class="page">
      <header class="page-head">
        <div class="eyebrow eyebrow-accent">Gatehouse</div>
        <h1 class="page-title page-title-small">Settings</h1>
      </header>
      <SettingsForm settings={data} onSaved={setData} />
      <NPMImport view={data} />
      <ConfigFile />
      <Discovery view={data} />
    </div>
  );
}

function SettingsForm(props: { settings: SettingsView; onSaved: (s: SettingsView) => void }) {
  const [s, setS] = useState<Settings>(props.settings);
  const [resolvers, setResolvers] = useState(props.settings.resolvers.join(", "));
  const [saved, setSaved] = useState(false);
  const act = useAction();
  useEffect(() => setSaved(false), [s, resolvers]);
  const dirty =
    JSON.stringify(s) !== JSON.stringify(props.settings) ||
    resolvers !== props.settings.resolvers.join(", ");
  useUnsavedWarning(dirty);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v });
  const v = props.settings;

  const submit = async (e: Event) => {
    e.preventDefault();
    const next = await act.run(() => api.saveSettings({ ...s, resolvers: splitList(resolvers) }));
    if (next) {
      props.onSaved(next);
      setS(next);
      setSaved(true);
    }
  };

  return (
    <form class="settings-form" onSubmit={submit}>
      <section class="section">
        <SectionHead index={1} title="Certificates" />
        <div class="form-grid">
          <Field label="ACME email" hint="Let's Encrypt's account; it may email about problems.">
            <input
              class="input"
              type="email"
              value={s.acme_email}
              onInput={(e) => set("acme_email", e.currentTarget.value)}
            />
          </Field>
          <Field
            label="DNS provider"
            hint={
              v.dns_token_set ? (
                "API token found in the environment."
              ) : (
                <span class="tone-warn">Set CF_DNS_API_TOKEN in Gatehouse's environment.</span>
              )
            }
          >
            <select
              class="input"
              value={s.dns_provider}
              onChange={(e) => set("dns_provider", e.currentTarget.value)}
            >
              {v.providers.map((p) => (
                <option key={p} value={p}>
                  {p[0].toUpperCase() + p.slice(1)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Renew with" hint="Days left.">
            <input
              class="input"
              type="number"
              min={1}
              value={s.renew_days}
              onInput={(e) => set("renew_days", Number(e.currentTarget.value))}
            />
          </Field>
          <Field label="Warn below" hint="Days left, for any certificate.">
            <input
              class="input"
              type="number"
              min={1}
              value={s.warn_days}
              onInput={(e) => set("warn_days", Number(e.currentTarget.value))}
            />
          </Field>
          <Field
            label="Propagation check resolvers"
            hint="Public DNS servers to see the challenge record before the CA looks."
            class="span-2"
          >
            <input
              class="input code"
              value={resolvers}
              onInput={(e) => setResolvers(e.currentTarget.value)}
            />
          </Field>
        </div>
        <label class="check">
          <input
            type="checkbox"
            checked={s.acme_staging}
            onChange={(e) => set("acme_staging", e.currentTarget.checked)}
          />
          Use Let's Encrypt's staging CA (for testing: untrusted certificates, generous limits)
        </label>
      </section>

      <section class="section">
        <SectionHead index={2} title="Notifications & logs" />
        <div class="form-grid">
          <Field
            label="Notify URL"
            hint="Apprise-style JSON, e.g. Lookout's http://lookout:8080/notify/<key>. For renewal failures and expiry warnings."
            class="span-2"
          >
            <input
              class="input code"
              value={s.notify_url}
              placeholder="http://lookout:8080/notify/gatehouse"
              onInput={(e) => set("notify_url", e.currentTarget.value)}
            />
          </Field>
          <Field label="Access log size" hint="Recent requests kept in memory.">
            <input
              class="input"
              type="number"
              min={100}
              step={100}
              value={s.access_log_size}
              onInput={(e) => set("access_log_size", Number(e.currentTarget.value))}
            />
          </Field>
        </div>
      </section>
      <div class="toolbar">
        <button class="btn btn-primary" disabled={act.busy || !dirty}>
          Save settings
        </button>
        {saved && <span class="tone-good">Saved.</span>}
        {act.error && <span class="form-error pre">{act.error}</span>}
      </div>
    </form>
  );
}

function NPMImport(props: { view: SettingsView }) {
  const [found, setFound] = useState<NPMFound | null>(null);
  const [report, setReport] = useState<NPMReport | null>(null);
  const act = useAction();
  const isOld = (domains: string[]) => domains.some((d) => found?.existing.includes(d));
  const fresh = found
    ? [...found.hosts, ...found.redirects].filter((x) => !isOld(x.domains)).length +
      found.certificates.filter((c) => c.found && !found.held_certificates.includes(c.name)).length
    : 0;
  const preview = async () => {
    setReport(null);
    const f = await act.run(api.previewNPM);
    if (f) setFound(f);
  };
  const run = async () => {
    const r = await act.run(api.importNPM);
    if (r) {
      setReport(r);
      setFound(null);
    }
  };
  return (
    <section class="section">
      <SectionHead index={3} title="Import from Nginx Proxy Manager" />
      <div class="import-card">
        <p class="muted">
          Reads NPM's database and certificates from its folder, mounted read-only. Hosts and
          redirects for domains Gatehouse already serves are skipped, and NPM is left untouched, so
          you can switch back at any time. Its Let's Encrypt certificates are copied and renewed
          from here on.
        </p>
        {props.view.npm_dir ? (
          <div class="muted">
            Folder: <code>{props.view.npm_dir}</code>
          </div>
        ) : (
          <div class="note note-warn">
            Mount NPM's folder, e.g. <code>./npm:/npm:ro</code>, to import from it.
          </div>
        )}
        <div class="toolbar">
          <button
            class="btn btn-ghost"
            onClick={preview}
            disabled={act.busy || !props.view.npm_dir}
          >
            Preview
          </button>
          {found && (
            <button class="btn btn-primary" onClick={run} disabled={act.busy || fresh === 0}>
              {fresh === 0 ? "Nothing new" : `Import ${plural(fresh, "new item")}`}
            </button>
          )}
        </div>
        {act.error && <div class="form-error pre">{act.error}</div>}
        {found && (
          <div class="npm-preview">
            <div class="eyebrow">
              {plural(found.hosts.length, "host")} · {plural(found.redirects.length, "redirect")} ·{" "}
              {plural(found.certificates.length, "certificate")}
            </div>
            <ul class="plain-list mono">
              {found.hosts.map((h) => (
                <li key={h.domains.join()} class={isOld(h.domains) ? "muted" : ""}>
                  {h.domains.join(", ")} <span class="muted">→ {h.upstream}</span>
                  {!h.enabled && <span class="chip">Off</span>}
                  {isOld(h.domains) && <span class="chip">Already set up</span>}
                </li>
              ))}
              {found.redirects.map((r) => (
                <li key={r.domains.join()} class={isOld(r.domains) ? "muted" : ""}>
                  {r.domains.join(", ")} <span class="muted">⇢ {r.target}</span>
                  {isOld(r.domains) && <span class="chip">Already set up</span>}
                </li>
              ))}
              {found.certificates.map((c) => (
                <li key={c.name}>
                  <span class="chip">Cert</span> {c.domains.join(", ")}{" "}
                  <span class="muted">
                    · {c.provider} · expires {c.expires}
                  </span>
                  {!c.found && <span class="chip chip-warn">files missing</span>}
                  {found.held_certificates.includes(c.name) && (
                    <span class="chip">Already held</span>
                  )}
                </li>
              ))}
            </ul>
            {found.warnings.length > 0 && (
              <div class="note note-warn">
                Not carried over:
                <ul>
                  {found.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
        {report && (
          <div class="note note-accent">
            Imported {plural(report.hosts, "host")}, {plural(report.redirects, "redirect")} and{" "}
            {plural(report.certificates, "certificate")}.
            {report.skipped.length > 0 && (
              <ul>
                {report.skipped.map((s) => (
                  <li key={s}>Skipped {s}</li>
                ))}
              </ul>
            )}
            {report.warnings.length > 0 && (
              <ul>
                {report.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function ConfigFile() {
  const act = useAction();
  const [done, setDone] = useState("");
  const importFile = async (file: File | undefined) => {
    if (!file) return;
    if (
      !confirm("Replace the whole configuration with this file? Hosts not in it stop being served.")
    ) {
      return;
    }
    setDone("");
    const r = await act.run(async () => api.importConfig(await file.text()));
    if (r) setDone(`Loaded ${plural(r.hosts, "host")} and ${plural(r.redirects, "redirect")}.`);
  };
  return (
    <section class="section">
      <SectionHead index={4} title="Configuration file" />
      <p class="muted">
        Every host, redirect and setting as YAML, to keep in the stacks repo. Basic-auth passwords
        are in it as bcrypt hashes; certificates and the DNS token are not. A file at{" "}
        <code>/data/gatehouse.yaml</code> is loaded on the very first start.
      </p>
      <div class="toolbar">
        <a class="btn btn-ghost" href="/api/config" download="gatehouse.yaml">
          <Download size={15} /> Export YAML
        </a>
        <label class="btn btn-ghost">
          <Upload size={15} /> Import YAML
          <input
            type="file"
            accept=".yaml,.yml"
            hidden
            onChange={(e) => {
              importFile(e.currentTarget.files?.[0]);
              e.currentTarget.value = "";
            }}
          />
        </label>
        {done && <span class="tone-good">{done}</span>}
      </div>
      {act.error && <div class="form-error pre">{act.error}</div>}
    </section>
  );
}

function Discovery(props: { view: SettingsView }) {
  return (
    <section class="section">
      <SectionHead index={5} title="Discovery API" />
      <p class="muted">
        A read-only list of hosts, upstreams, certificate expiry and sleep state, for Foyer's
        topology and Lookout's checks. Call it with the{" "}
        {props.view.discovery_token_set ? (
          <>
            read-only <code>GATEHOUSE_DISCOVERY_TOKEN</code>
          </>
        ) : (
          <>
            admin token (set <code>GATEHOUSE_DISCOVERY_TOKEN</code> for a read-only one)
          </>
        )}{" "}
        as a bearer token.
      </p>
      <CopyField value={`${location.origin}/api/discovery`} label="Copy the discovery URL" />
      <p class="muted">
        Scale-to-zero:{" "}
        {props.view.docker
          ? "the Docker API is reachable."
          : "no Docker socket, so idle stop is off."}
      </p>
    </section>
  );
}
