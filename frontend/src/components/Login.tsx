import { useState } from "preact/hooks";
import { api } from "../api";
import type { Session } from "../types";

export function Login(props: { onDone: (s: Session) => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      props.onDone(await api.login(token));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="login">
      <form class="login-card" onSubmit={submit}>
        <div class="eyebrow eyebrow-accent">Gatehouse</div>
        <h1 class="login-title">Sign in</h1>
        <p class="muted">
          Enter the token from <code>GATEHOUSE_TOKEN</code>. This browser stays signed in until the
          token changes.
        </p>
        <input
          class="input code"
          type="password"
          autocomplete="current-password"
          placeholder="Token"
          value={token}
          autofocus
          onInput={(e) => setToken(e.currentTarget.value)}
        />
        {error && <div class="form-error">{error}</div>}
        <button class="btn btn-primary" disabled={!token || busy}>
          Sign in
        </button>
      </form>
    </div>
  );
}
