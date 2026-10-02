import { Plus, Trash2 } from "lucide-preact";
import { useState } from "preact/hooks";
import { api } from "../api";
import { useUnsavedWarning } from "../hooks";
import { formatHeaders, parseHeaders, splitList } from "../lib";
import type { BasicUser, Host, HostView, TestResult } from "../types";
import { Dialog, Dot, Field, useAction } from "./ui";

interface Draft {
  domains: string;
  upstream: string;
  insecure: boolean;
  enabled: boolean;
  forceHTTPS: boolean;
  hsts: boolean;
  maxBody: string;
  timeout: string;
  allow: string;
  users: BasicUser[];
  requestHeaders: string;
  responseHeaders: string;
  idleStop: string;
  container: string;
}

function draftOf(h: HostView | null): Draft {
  return {
    domains: (h?.domains ?? []).join("\n"),
    upstream: h?.upstream ?? "",
    insecure: h?.insecure_upstream ?? false,
    enabled: h?.enabled ?? true,
    forceHTTPS: h?.force_https ?? true,
    hsts: h?.hsts ?? false,
    maxBody: h?.max_body_mb ? String(h.max_body_mb) : "",
    timeout: h?.timeout ?? "",
    allow: (h?.allow ?? []).join("\n"),
    users: (h?.basic_auth ?? []).map((u) => ({ user: u.user, password: "" })),
    requestHeaders: formatHeaders(h?.request_headers),
    responseHeaders: formatHeaders(h?.response_headers),
    idleStop: h?.idle_stop ?? "",
    container: h?.container ?? "",
  };
}

function hostOf(d: Draft, id?: string): Partial<Host> {
  return {
    id,
    domains: splitList(d.domains),
    upstream: d.upstream.trim(),
    insecure_upstream: d.insecure,
    enabled: d.enabled,
    force_https: d.forceHTTPS,
    hsts: d.hsts,
    max_body_mb: Number(d.maxBody) || 0,
    timeout: d.timeout.trim(),
    allow: splitList(d.allow),
    basic_auth: d.users
      .filter((u) => u.user.trim())
      .map((u) => ({ user: u.user.trim(), password: u.password || undefined })),
    request_headers: parseHeaders(d.requestHeaders),
    response_headers: parseHeaders(d.responseHeaders),
    idle_stop: d.idleStop.trim(),
    container: d.idleStop.trim() ? d.container.trim() : "",
  };
}

export function HostForm(props: {
  host: HostView | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const initial = draftOf(props.host);
  const [d, setD] = useState<Draft>(initial);
  const [test, setTest] = useState<TestResult | null>(null);
  const save = useAction();
  const tester = useAction();
  const dirty = JSON.stringify(d) !== JSON.stringify(initial);
  useUnsavedWarning(dirty);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD({ ...d, [k]: v });
  const isNew = !props.host;

  const submit = async (e: Event) => {
    e.preventDefault();
    const ok = await save.run(() => api.saveHost(hostOf(d, props.host?.id)));
    if (ok) props.onSaved();
  };
  const remove = async () => {
    if (
      !props.host ||
      !confirm(`Delete ${props.host.domains[0]}? It stops being served at once.`)
    ) {
      return;
    }
    await save.run(async () => {
      await api.deleteHost(props.host!.id);
      props.onSaved();
    });
  };
  const runTest = async () => {
    setTest(null);
    const r = await tester.run(() => api.testHost(hostOf(d)));
    if (r) setTest(r);
  };
  const close = () => {
    if (!dirty || confirm("Discard your changes?")) props.onClose();
  };

  return (
    <Dialog
      title={isNew ? "Add host" : props.host!.domains[0]}
      onClose={close}
      wide
      footer={
        <>
          {!isNew && (
            <button
              class="btn btn-ghost btn-danger"
              type="button"
              onClick={remove}
              disabled={save.busy}
            >
              <Trash2 size={15} /> Delete
            </button>
          )}
          <span class="spacer" />
          <button class="btn btn-ghost" type="button" onClick={runTest} disabled={tester.busy}>
            {tester.busy ? "Testing…" : "Test"}
          </button>
          <button class="btn btn-primary" type="submit" form="host-form" disabled={save.busy}>
            {isNew ? "Add host" : "Save"}
          </button>
        </>
      }
    >
      <form id="host-form" class="stack-form" onSubmit={submit}>
        <div class="form-grid">
          <Field
            label="Domains"
            hint="One per line. *.example.com covers every subdomain."
            class="span-2"
          >
            <textarea
              class="input code"
              rows={3}
              value={d.domains}
              placeholder="books.example.com"
              autofocus={isNew}
              onInput={(e) => set("domains", e.currentTarget.value)}
            />
          </Field>
          <Field
            label="Upstream"
            hint="Container and port on a shared network, or host.docker.internal:port."
            class="span-2"
          >
            <input
              class="input code"
              value={d.upstream}
              placeholder="http://shelfloom:8000"
              onInput={(e) => set("upstream", e.currentTarget.value)}
            />
          </Field>
        </div>
        <div class="checks-row">
          <label class="check">
            <input
              type="checkbox"
              checked={d.enabled}
              onChange={(e) => set("enabled", e.currentTarget.checked)}
            />
            Enabled
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={d.forceHTTPS}
              onChange={(e) => set("forceHTTPS", e.currentTarget.checked)}
            />
            Redirect HTTP to HTTPS
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={d.hsts}
              onChange={(e) => set("hsts", e.currentTarget.checked)}
            />
            HSTS
          </label>
          {d.upstream.trim().startsWith("https://") && (
            <label class="check">
              <input
                type="checkbox"
                checked={d.insecure}
                onChange={(e) => set("insecure", e.currentTarget.checked)}
              />
              Don't verify the upstream's certificate
            </label>
          )}
        </div>

        {test && <TestReport result={test} />}
        {tester.error && <div class="form-error">{tester.error}</div>}

        <fieldset class="fieldset">
          <legend class="eyebrow">Access</legend>
          <div class="form-grid halves">
            <Field
              label="Allow only"
              hint="CIDRs or addresses, e.g. 100.64.0.0/10 for the tailnet. Empty allows all."
            >
              <textarea
                class="input code"
                rows={2}
                value={d.allow}
                onInput={(e) => set("allow", e.currentTarget.value)}
              />
            </Field>
            <div class="field">
              <span class="field-label">Password (basic auth)</span>
              {d.users.map((u, i) => (
                <div key={i} class="user-row">
                  <input
                    class="input"
                    placeholder="User"
                    value={u.user}
                    onInput={(e) => {
                      const users = [...d.users];
                      users[i] = { ...u, user: e.currentTarget.value };
                      set("users", users);
                    }}
                  />
                  <input
                    class="input"
                    type="password"
                    autocomplete="new-password"
                    placeholder={
                      props.host?.basic_auth?.some((x) => x.user === u.user)
                        ? "Unchanged"
                        : "Password"
                    }
                    value={u.password ?? ""}
                    onInput={(e) => {
                      const users = [...d.users];
                      users[i] = { ...u, password: e.currentTarget.value };
                      set("users", users);
                    }}
                  />
                  <button
                    class="icon-btn"
                    type="button"
                    aria-label="Remove user"
                    onClick={() =>
                      set(
                        "users",
                        d.users.filter((_, j) => j !== i),
                      )
                    }
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}
              <button
                class="btn btn-ghost btn-small"
                type="button"
                onClick={() => set("users", [...d.users, { user: "", password: "" }])}
              >
                <Plus size={14} /> User
              </button>
            </div>
          </div>
        </fieldset>

        <fieldset class="fieldset">
          <legend class="eyebrow">Scale to zero</legend>
          <div class="form-grid">
            <Field label="Stop after idle" hint="e.g. 30m. Empty keeps it running.">
              <input
                class="input code"
                value={d.idleStop}
                placeholder="30m"
                onInput={(e) => set("idleStop", e.currentTarget.value)}
              />
            </Field>
            <Field label="Container" hint="The one to stop and start.">
              <input
                class="input code"
                value={d.container}
                disabled={!d.idleStop.trim()}
                placeholder="convertx"
                onInput={(e) => set("container", e.currentTarget.value)}
              />
            </Field>
          </div>
        </fieldset>

        <fieldset class="fieldset">
          <legend class="eyebrow">Advanced</legend>
          <div class="form-grid">
            <Field label="Max upload (MB)" hint="Empty: no limit.">
              <input
                class="input"
                type="number"
                min={0}
                value={d.maxBody}
                onInput={(e) => set("maxBody", e.currentTarget.value)}
              />
            </Field>
            <Field
              label="Response timeout"
              hint="Wait for the upstream's headers, e.g. 60s. Empty: no limit."
            >
              <input
                class="input code"
                value={d.timeout}
                onInput={(e) => set("timeout", e.currentTarget.value)}
              />
            </Field>
            <Field label="Request headers" hint="Name: value, one per line. Sent to the upstream.">
              <textarea
                class="input code"
                rows={2}
                value={d.requestHeaders}
                onInput={(e) => set("requestHeaders", e.currentTarget.value)}
              />
            </Field>
            <Field label="Response headers" hint="Name: value, one per line. Sent to the browser.">
              <textarea
                class="input code"
                rows={2}
                value={d.responseHeaders}
                onInput={(e) => set("responseHeaders", e.currentTarget.value)}
              />
            </Field>
          </div>
        </fieldset>
        {save.error && <div class="form-error pre">{save.error}</div>}
      </form>
    </Dialog>
  );
}

function TestReport(props: { result: TestResult }) {
  const { upstream, dns } = props.result;
  return (
    <ul class="test-report">
      <li>
        <Dot tone={upstream.ok ? "good" : "bad"} />
        <span>
          <strong>Upstream</strong> <span class="muted">{upstream.message}</span>
        </span>
      </li>
      {dns.map((r) => (
        <li key={r.domain}>
          <Dot tone={r.error ? "warn" : r.certificate ? "good" : "warn"} />
          <span>
            <strong>{r.domain}</strong>{" "}
            <span class="muted">
              {r.error ? "doesn't resolve" : `resolves to ${r.addresses.join(", ")}`} ·{" "}
              {r.certificate
                ? `certificate ${r.certificate.name} (${r.certificate.days_left}d)`
                : "no certificate"}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}
