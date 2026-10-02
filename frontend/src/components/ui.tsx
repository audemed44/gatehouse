import { Check as CheckIcon, Copy, X } from "lucide-preact";
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { Tone } from "../lib";

/** A modal built on <dialog>, so focus trapping and Escape come for free. */
export function Dialog(props: {
  title: string;
  onClose: () => void;
  children: ComponentChildren;
  footer?: ComponentChildren;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      class={`dialog ${props.wide ? "dialog-wide" : ""}`}
      onCancel={(e) => {
        e.preventDefault();
        props.onClose();
      }}
      onClick={(e) => e.target === ref.current && props.onClose()}
    >
      <div class="dialog-inner">
        <div class="dialog-head">
          <h2>{props.title}</h2>
          <button class="icon-btn" onClick={props.onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div class="dialog-body">{props.children}</div>
        {props.footer && <div class="dialog-foot">{props.footer}</div>}
      </div>
    </dialog>
  );
}

export function Field(props: {
  label: string;
  hint?: ComponentChildren;
  children: ComponentChildren;
  class?: string;
}) {
  return (
    <label class={`field ${props.class ?? ""}`}>
      <span class="field-label">{props.label}</span>
      {props.children}
      {props.hint && <span class="field-hint">{props.hint}</span>}
    </label>
  );
}

export function Dot(props: { tone: Tone; title?: string }) {
  return <span class={`dot ${props.tone}`} title={props.title} />;
}

/** A numbered heading over a heavy rule, as on Foyer. */
export function SectionHead(props: {
  index?: number;
  title: string;
  children?: ComponentChildren;
}) {
  return (
    <div class="section-head">
      {props.index !== undefined && (
        <span class="section-index">{String(props.index).padStart(2, "0")}</span>
      )}
      <h2 class="section-name">{props.title}</h2>
      <span class="spacer" />
      {props.children}
    </div>
  );
}

export function ErrorNote(props: { children: ComponentChildren }) {
  return <div class="note note-bad">{props.children}</div>;
}

export function Figure(props: {
  value: string | number;
  unit?: string;
  label: string;
  tone?: string;
  title?: string;
}) {
  return (
    <div class={`figure ${props.tone ?? ""}`} title={props.title}>
      <div class="figure-value">
        {props.value}
        {props.unit && <span class="figure-unit">{props.unit}</span>}
      </div>
      <div class="eyebrow figure-label">{props.label}</div>
    </div>
  );
}

/** A value in a mono box with a copy button. */
export function CopyField(props: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard needs a secure context; the text is selectable anyway
    }
  };
  return (
    <div class="copy-field">
      <code title={props.value}>{props.value}</code>
      <button
        class="icon-btn"
        type="button"
        onClick={copy}
        aria-label={props.label ?? "Copy"}
        title="Copy"
      >
        {copied ? <CheckIcon size={15} /> : <Copy size={15} />}
      </button>
    </div>
  );
}

/** Runs an async action with busy and error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError("");
    try {
      return await fn();
    } catch (e) {
      setError((e as Error).message);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

export function Empty(props: { children: ComponentChildren }) {
  return <div class="empty">{props.children}</div>;
}
