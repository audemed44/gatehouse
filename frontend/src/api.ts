import type {
  Certificate,
  Host,
  HostStats,
  HostView,
  LogEntry,
  NPMFound,
  NPMReport,
  Overview,
  Redirect,
  RedirectView,
  Session,
  Settings,
  SettingsView,
  TestResult,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** Called when the session has expired, so the app can show the sign-in. */
let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      message = (await res.json()).error ?? message;
    } catch {
      // not JSON
    }
    if (res.status === 401 && !path.startsWith("/api/session")) onUnauthorized();
    throw new ApiError(message, res.status);
  }
  if (res.status === 204 || res.status === 202) return undefined as T;
  const type = res.headers.get("Content-Type") ?? "";
  return (type.includes("json") ? res.json() : res.text()) as Promise<T>;
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const post = { method: "POST" };
const del = { method: "DELETE" };
const enc = encodeURIComponent;

export const api = {
  session: () => request<Session>("/api/session"),
  login: (token: string) => request<Session>("/api/session", json("POST", { token })),
  logout: () => request<void>("/api/session", del),

  overview: () => request<Overview>("/api/overview"),

  hosts: () => request<HostView[]>("/api/hosts"),
  saveHost: (h: Partial<Host>) =>
    h.id
      ? request<HostView>(`/api/hosts/${enc(h.id)}`, json("PUT", h))
      : request<HostView>("/api/hosts", json("POST", h)),
  deleteHost: (id: string) => request<void>(`/api/hosts/${enc(id)}`, del),
  testHost: (h: Partial<Host>) => request<TestResult>("/api/hosts/test", json("POST", h)),
  wake: (id: string) => request<void>(`/api/hosts/${enc(id)}/wake`, post),
  sleep: (id: string) => request<void>(`/api/hosts/${enc(id)}/sleep`, post),

  redirects: () => request<RedirectView[]>("/api/redirects"),
  saveRedirect: (r: Partial<Redirect>) =>
    r.id
      ? request<Redirect>(`/api/redirects/${enc(r.id)}`, json("PUT", r))
      : request<Redirect>("/api/redirects", json("POST", r)),
  deleteRedirect: (id: string) => request<void>(`/api/redirects/${enc(id)}`, del),

  certificates: () => request<Certificate[]>("/api/certificates"),
  requestCert: (domains: string[]) => request<void>("/api/certificates", json("POST", { domains })),
  renewCert: (name: string) => request<void>(`/api/certificates/${enc(name)}/renew`, post),
  deleteCert: (name: string) => request<void>(`/api/certificates/${enc(name)}`, del),
  uploadCert: (files: { cert?: File; key?: File; pem?: string }) => {
    const form = new FormData();
    if (files.cert) form.set("cert", files.cert);
    if (files.key) form.set("key", files.key);
    if (files.pem) form.set("pem", files.pem);
    return request<Certificate>("/api/certificates/upload", { method: "POST", body: form });
  },

  logs: (host: string, errors: boolean) =>
    request<{ entries: LogEntry[]; stats: HostStats[] }>(
      `/api/logs?limit=300${host ? `&host=${enc(host)}` : ""}${errors ? "&errors=1" : ""}`,
    ),

  settings: () => request<SettingsView>("/api/settings"),
  saveSettings: (s: Settings) => request<SettingsView>("/api/settings", json("PUT", s)),
  previewNPM: () => request<NPMFound>("/api/npm"),
  importNPM: () => request<NPMReport>("/api/npm", post),
  importConfig: (yaml: string) =>
    request<{ hosts: number; redirects: number }>("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/yaml" },
      body: yaml,
    }),
};
