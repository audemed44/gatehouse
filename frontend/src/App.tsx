import { LogOut } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import { api, setUnauthorizedHandler } from "./api";
import { CertificatesPage } from "./components/CertificatesPage";
import { HostsPage } from "./components/HostsPage";
import { Login } from "./components/Login";
import { LogsPage } from "./components/LogsPage";
import { SettingsPage } from "./components/SettingsPage";
import { onLinkClick, useRoute, type Route } from "./router";
import type { Session } from "./types";

export function App() {
  const route = useRoute();
  const [session, setSession] = useState<Session | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setUnauthorizedHandler(() => setSession({ authenticated: false }));
    api
      .session()
      .then(setSession)
      .catch((e: Error) => setError(e.message));
  }, []);

  if (error) return <div class="boot">Can't reach Gatehouse: {error}</div>;
  if (!session) return <div class="boot" />;
  if (!session.authenticated) return <Login onDone={setSession} />;
  return <Shell route={route} onSignOut={() => setSession({ authenticated: false })} />;
}

const NAV: { page: Route["page"]; href: string; label: string }[] = [
  { page: "hosts", href: "/", label: "Hosts" },
  { page: "certificates", href: "/certificates", label: "Certificates" },
  { page: "logs", href: "/logs", label: "Logs" },
  { page: "settings", href: "/settings", label: "Settings" },
];

function Shell(props: { route: Route; onSignOut: () => void }) {
  const { route } = props;
  const signOut = async () => {
    await api.logout().catch(() => {});
    props.onSignOut();
  };
  return (
    <div class="shell" onClick={onLinkClick}>
      <header class="topbar">
        <a class="brand" href="/">
          <span class="brand-mark" aria-hidden="true" />
          <span class="brand-name">Gatehouse</span>
        </a>
        <span class="spacer" />
        <nav class="topnav" aria-label="Pages">
          {NAV.map((n) => (
            <a key={n.page} class={route.page === n.page ? "active" : ""} href={n.href}>
              {n.label}
            </a>
          ))}
        </nav>
        <button class="icon-btn" onClick={signOut} title="Sign out" aria-label="Sign out">
          <LogOut size={16} />
        </button>
      </header>
      <main>
        {route.page === "hosts" && <HostsPage />}
        {route.page === "certificates" && <CertificatesPage />}
        {route.page === "logs" && <LogsPage key={route.host} host={route.host} />}
        {route.page === "settings" && <SettingsPage />}
      </main>
    </div>
  );
}
