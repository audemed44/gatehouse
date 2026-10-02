export interface Session {
  authenticated: boolean;
}

export interface BasicUser {
  user: string;
  password?: string;
}

export interface Host {
  id: string;
  domains: string[];
  upstream: string;
  insecure_upstream?: boolean;
  enabled: boolean;
  force_https?: boolean;
  hsts?: boolean;
  max_body_mb?: number;
  timeout?: string;
  request_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  allow?: string[];
  basic_auth?: BasicUser[];
  idle_stop?: string;
  container?: string;
}

export interface CertRef {
  name: string;
  not_after: string;
  days_left: number;
}

export type SleepState = "awake" | "stopping" | "sleeping" | "waking";

export interface SleepStatus {
  container: string;
  state: SleepState;
  since: string;
  idle_stop: string;
  last_active: string;
  active: number;
  error?: string;
}

export interface HostStats {
  host: string;
  requests: number;
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_5xx: number;
  asleep: number; // monitor probes answered while the app slept
  bytes: number;
  last_seen: string;
}

export interface HostView extends Host {
  certificate: CertRef | null;
  uncovered: string[];
  sleep: SleepStatus | null;
  stats: HostStats | null;
}

export interface Redirect {
  id: string;
  domains: string[];
  target: string;
  code: number;
  preserve_path: boolean;
  enabled: boolean;
  force_https?: boolean;
}

export interface RedirectView extends Redirect {
  certificate: CertRef | null;
}

export interface Certificate {
  name: string;
  domains: string[];
  not_before: string;
  not_after: string;
  issuer: string;
  source: string;
  last_renewal?: string;
  last_error?: string;
  last_attempt?: string;
  days_left: number;
  managed: boolean;
  renewing: boolean;
  missing: boolean;
  hosts: string[];
}

export interface LogEntry {
  time: string;
  host: string;
  method: string;
  path: string;
  status: number;
  bytes: number;
  ms: number;
  client: string;
  tls: boolean;
  matched: boolean;
  asleep?: boolean;
}

export interface Overview {
  hosts: number;
  enabled: number;
  redirects: number;
  certificates: Certificate[];
  sleep: SleepStatus[];
  stats: HostStats[];
  recent_errors: LogEntry[];
  docker: boolean;
}

export interface Settings {
  acme_email: string;
  acme_staging: boolean;
  dns_provider: string;
  resolvers: string[];
  renew_days: number;
  warn_days: number;
  notify_url: string;
  certificates: string[][];
  access_log_size: number;
}

export interface SettingsView extends Settings {
  dns_token_set: boolean;
  providers: string[];
  npm_dir: string;
  discovery_token_set: boolean;
  docker: boolean;
}

export interface TestResult {
  upstream: { ok: boolean; status?: number; ms: number; message: string };
  dns: { domain: string; addresses: string[]; error?: string; certificate: CertRef | null }[];
}

export interface NPMCert {
  name: string;
  domains: string[];
  provider: string;
  expires: string;
  dns_provider?: string;
  found: boolean;
}

export interface NPMFound {
  hosts: Host[];
  redirects: Redirect[];
  certificates: NPMCert[];
  warnings: string[];
  existing: string[]; // domains Gatehouse already serves; skipped
  held_certificates: string[];
}

export interface NPMReport {
  hosts: number;
  redirects: number;
  certificates: number;
  skipped: string[];
  warnings: string[];
}
