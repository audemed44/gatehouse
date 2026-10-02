import { RefreshCw, Trash2, Upload } from "lucide-preact";
import { useState } from "preact/hooks";
import { api } from "../api";
import { useData } from "../hooks";
import { ago, certTone, day, plural, splitList } from "../lib";
import type { Certificate, SettingsView } from "../types";
import { Dialog, Empty, ErrorNote, Field, SectionHead, useAction } from "./ui";

const SOURCE: Record<string, string> = {
  acme: "Let's Encrypt",
  "acme-staging": "Staging",
  npm: "From NPM",
  upload: "Uploaded",
};

export function CertificatesPage() {
  const certs = useData(api.certificates, 5_000);
  const settings = useData(api.settings);
  const [requesting, setRequesting] = useState(false);
  const [uploading, setUploading] = useState(false);

  if (!certs.data) {
    return certs.error ? (
      <ErrorNote>{certs.error}</ErrorNote>
    ) : (
      <div class="skeleton page-skeleton" />
    );
  }
  const s = settings.data;
  return (
    <div class="page">
      <header class="page-head">
        <div class="eyebrow eyebrow-accent">
          {plural(certs.data.filter((c) => !c.missing).length, "certificate")} · picked by name for
          each request
        </div>
        <h1 class="page-title page-title-small">Certificates</h1>
        <p class="page-lede muted">
          Issued by Let's Encrypt over DNS-01, so nothing needs to be reachable from the internet.
          Renewed with {s?.renew_days ?? 30} days left; a warning goes out below{" "}
          {s?.warn_days ?? 14} days, whatever the cause.
        </p>
        <Warnings settings={s} />
      </header>
      <div class="toolbar">
        <span class="spacer" />
        <button class="btn btn-ghost" onClick={() => setUploading(true)}>
          <Upload size={15} /> Upload
        </button>
        <button class="btn btn-primary" onClick={() => setRequesting(true)}>
          Request certificate
        </button>
      </div>
      <section class="section">
        <SectionHead index={1} title="Held" />
        {certs.data.length === 0 ? (
          <Empty>
            No certificates yet. Request a wildcard like *.example.com, or import Nginx Proxy
            Manager's in{" "}
            <a class="link-btn" href="/settings">
              Settings
            </a>
            .
          </Empty>
        ) : (
          <div class="cert-list stagger">
            {certs.data.map((c) => (
              <CertCard key={c.name} cert={c} warnDays={s?.warn_days} onChanged={certs.reload} />
            ))}
          </div>
        )}
      </section>
      {requesting && (
        <RequestDialog
          onClose={() => setRequesting(false)}
          onDone={() => {
            setRequesting(false);
            certs.reload();
          }}
        />
      )}
      {uploading && (
        <UploadDialog
          onClose={() => setUploading(false)}
          onDone={() => {
            setUploading(false);
            certs.reload();
          }}
        />
      )}
    </div>
  );
}

function Warnings(props: { settings: SettingsView | null }) {
  const s = props.settings;
  if (!s) return null;
  return (
    <>
      {!s.dns_token_set && (
        <div class="note note-warn">
          <code>CF_DNS_API_TOKEN</code> isn't set, so certificates can't be issued or renewed. Give
          Gatehouse a Cloudflare API token with Zone · DNS · Edit in its environment.
        </div>
      )}
      {s.acme_staging && (
        <div class="note note-accent">
          Using Let's Encrypt's staging CA: new certificates won't be trusted by browsers.
        </div>
      )}
    </>
  );
}

function CertCard(props: { cert: Certificate; warnDays?: number; onChanged: () => void }) {
  const c = props.cert;
  const act = useAction();
  const tone = c.missing ? "warn" : certTone(c.days_left, props.warnDays);
  const renew = () =>
    act.run(async () => {
      await api.renewCert(c.name);
      props.onChanged();
    });
  const remove = () => {
    const msg = c.managed
      ? `Delete ${c.name} and stop renewing it? Hosts it covers fall back to plain HTTP.`
      : `Delete ${c.name}? Hosts it covers fall back to plain HTTP.`;
    if (!confirm(msg)) return;
    act.run(async () => {
      await api.deleteCert(c.name);
      props.onChanged();
    });
  };
  return (
    <article class="cert-card">
      <div class={`figure ${tone === "good" ? "" : tone}`}>
        <div class="figure-value">
          {c.missing ? "—" : c.days_left}
          {!c.missing && <span class="figure-unit">d</span>}
        </div>
        <div class="eyebrow figure-label">
          {c.missing ? "Not issued yet" : `Until ${day(c.not_after)}`}
        </div>
      </div>
      <div class="cert-main">
        <div class="cert-title">{c.domains.join(", ")}</div>
        <div class="chips">
          {c.managed ? (
            <span class="chip chip-accent">Auto-renew</span>
          ) : (
            <span class="chip">Not renewed</span>
          )}
          {c.source && <span class="chip">{SOURCE[c.source] ?? c.source}</span>}
          {c.renewing && <span class="chip chip-accent">Issuing…</span>}
          {c.issuer && <span class="muted cert-issuer">{c.issuer}</span>}
        </div>
        <div class="muted cert-meta">
          {c.hosts.length > 0 ? `Serves ${plural(c.hosts.length, "domain")}` : "Serves nothing yet"}
          {ago(c.last_renewal) && ` · renewed ${ago(c.last_renewal)}`}
          {ago(c.last_attempt) && c.last_error && ` · last tried ${ago(c.last_attempt)}`}
        </div>
        {c.last_error && <div class="note note-bad pre">{c.last_error}</div>}
        {act.error && <div class="form-error">{act.error}</div>}
      </div>
      <div class="cert-actions">
        {c.managed && (
          <button class="btn btn-ghost btn-small" onClick={renew} disabled={act.busy || c.renewing}>
            <RefreshCw size={14} class={c.renewing ? "spin" : ""} /> {c.missing ? "Issue" : "Renew"}
          </button>
        )}
        <button
          class="icon-btn"
          onClick={remove}
          disabled={act.busy}
          title="Delete"
          aria-label="Delete"
        >
          <Trash2 size={15} />
        </button>
      </div>
    </article>
  );
}

function RequestDialog(props: { onClose: () => void; onDone: () => void }) {
  const [domains, setDomains] = useState("");
  const act = useAction();
  const submit = async (e: Event) => {
    e.preventDefault();
    await act.run(async () => {
      await api.requestCert(splitList(domains));
      props.onDone();
    });
  };
  return (
    <Dialog
      title="Request a certificate"
      onClose={props.onClose}
      footer={
        <button class="btn btn-primary" type="submit" form="request-form" disabled={act.busy}>
          Request
        </button>
      }
    >
      <form id="request-form" class="stack-form" onSubmit={submit}>
        <Field
          label="Domains"
          hint="A wildcard and the bare domain cover everything: *.example.com and example.com."
        >
          <textarea
            class="input code"
            rows={3}
            autofocus
            value={domains}
            placeholder={"*.example.com\nexample.com"}
            onInput={(e) => setDomains(e.currentTarget.value)}
          />
        </Field>
        <p class="muted">
          It's issued in the background (a minute or two while DNS propagates) and renewed from then
          on. A certificate with the same first domain is replaced.
        </p>
        {act.error && <div class="form-error pre">{act.error}</div>}
      </form>
    </Dialog>
  );
}

function UploadDialog(props: { onClose: () => void; onDone: () => void }) {
  const [cert, setCert] = useState<File | undefined>();
  const [key, setKey] = useState<File | undefined>();
  const [pem, setPem] = useState("");
  const act = useAction();
  const submit = async (e: Event) => {
    e.preventDefault();
    await act.run(async () => {
      await api.uploadCert({ cert, key, pem });
      props.onDone();
    });
  };
  return (
    <Dialog
      title="Upload a certificate"
      onClose={props.onClose}
      footer={
        <button
          class="btn btn-primary"
          type="submit"
          form="upload-form"
          disabled={act.busy || (!cert && !pem.trim())}
        >
          Upload
        </button>
      }
    >
      <form id="upload-form" class="stack-form" onSubmit={submit}>
        <p class="muted">
          For certificates from elsewhere. They're served but not renewed; you'll get a warning
          before one expires.
        </p>
        <div class="form-grid">
          <Field label="Certificate (fullchain.pem)">
            <input
              class="input"
              type="file"
              accept=".pem,.crt,.cer"
              onChange={(e) => setCert(e.currentTarget.files?.[0])}
            />
          </Field>
          <Field label="Private key (privkey.pem)">
            <input
              class="input"
              type="file"
              accept=".pem,.key"
              onChange={(e) => setKey(e.currentTarget.files?.[0])}
            />
          </Field>
        </div>
        <Field label="Or paste both" hint="The certificate chain and the key, in PEM.">
          <textarea
            class="input code"
            rows={5}
            value={pem}
            onInput={(e) => setPem(e.currentTarget.value)}
          />
        </Field>
        {act.error && <div class="form-error pre">{act.error}</div>}
      </form>
    </Dialog>
  );
}
