import { Trash2 } from "lucide-preact";
import { useState } from "preact/hooks";
import { api } from "../api";
import { splitList } from "../lib";
import type { RedirectView } from "../types";
import { Dialog, Field, useAction } from "./ui";

const CODES = [
  [301, "301 · moved permanently"],
  [302, "302 · found (temporary)"],
  [307, "307 · temporary, keeps the method"],
  [308, "308 · permanent, keeps the method"],
] as const;

export function RedirectForm(props: {
  redirect: RedirectView | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const r = props.redirect;
  const [domains, setDomains] = useState((r?.domains ?? []).join("\n"));
  const [target, setTarget] = useState(r?.target ?? "");
  const [code, setCode] = useState(r?.code ?? 301);
  const [preserve, setPreserve] = useState(r?.preserve_path ?? true);
  const [enabled, setEnabled] = useState(r?.enabled ?? true);
  const [forceHTTPS, setForceHTTPS] = useState(r?.force_https ?? true);
  const act = useAction();

  const submit = async (e: Event) => {
    e.preventDefault();
    await act.run(async () => {
      await api.saveRedirect({
        id: r?.id,
        domains: splitList(domains),
        target: target.trim(),
        code,
        preserve_path: preserve,
        enabled,
        force_https: forceHTTPS,
      });
      props.onSaved();
    });
  };
  const remove = async () => {
    if (!r || !confirm(`Delete the redirect for ${r.domains[0]}?`)) return;
    await act.run(async () => {
      await api.deleteRedirect(r.id);
      props.onSaved();
    });
  };

  return (
    <Dialog
      title={r ? r.domains[0] : "Add redirect"}
      onClose={props.onClose}
      footer={
        <>
          {r && (
            <button
              class="btn btn-ghost btn-danger"
              type="button"
              onClick={remove}
              disabled={act.busy}
            >
              <Trash2 size={15} /> Delete
            </button>
          )}
          <span class="spacer" />
          <button class="btn btn-primary" type="submit" form="redirect-form" disabled={act.busy}>
            {r ? "Save" : "Add redirect"}
          </button>
        </>
      }
    >
      <form id="redirect-form" class="stack-form" onSubmit={submit}>
        <Field label="Domains" hint="One per line.">
          <textarea
            class="input code"
            rows={2}
            value={domains}
            autofocus={!r}
            onInput={(e) => setDomains(e.currentTarget.value)}
          />
        </Field>
        <Field label="Send to" hint="A URL, or a domain (https:// is assumed).">
          <input
            class="input code"
            value={target}
            placeholder="books.example.com"
            onInput={(e) => setTarget(e.currentTarget.value)}
          />
        </Field>
        <Field label="Status">
          <select
            class="input"
            value={code}
            onChange={(e) => setCode(Number(e.currentTarget.value))}
          >
            {CODES.map(([c, label]) => (
              <option key={c} value={c}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <div class="checks-row">
          <label class="check">
            <input
              type="checkbox"
              checked={preserve}
              onChange={(e) => setPreserve(e.currentTarget.checked)}
            />
            Keep the path and query
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={forceHTTPS}
              onChange={(e) => setForceHTTPS(e.currentTarget.checked)}
            />
            HTTP to HTTPS first
          </label>
          <label class="check">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.currentTarget.checked)}
            />
            Enabled
          </label>
        </div>
        {act.error && <div class="form-error pre">{act.error}</div>}
      </form>
    </Dialog>
  );
}
