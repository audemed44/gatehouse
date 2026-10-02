import { useEffect, useState } from "preact/hooks";

/**
 * Path routes (the server answers every non-API path with the app):
 *   /                hosts and redirects
 *   /certificates    certificates, renewals, uploads
 *   /logs            recent requests
 *   /settings        ACME, notifications, NPM import, configuration
 */
export type Route =
  | { page: "hosts" }
  | { page: "certificates" }
  | { page: "logs"; host: string }
  | { page: "settings" };

export function parseRoute(path: string, search = ""): Route {
  const parts = path.split("/").filter(Boolean);
  switch (parts[0]) {
    case "certificates":
    case "settings":
      return { page: parts[0] };
    case "logs":
      return { page: "logs", host: new URLSearchParams(search).get("host") ?? "" };
  }
  return { page: "hosts" };
}

const listeners = new Set<() => void>();

export function navigate(url: string, replace = false) {
  if (url === window.location.pathname + window.location.search) return;
  if (replace) history.replaceState(null, "", url);
  else history.pushState(null, "", url);
  window.scrollTo(0, 0);
  listeners.forEach((fn) => fn());
}

/** Lets plain <a href="/…"> links navigate without a page load. */
export function onLinkClick(e: MouseEvent) {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
    return;
  }
  const a = (e.target as Element).closest("a");
  if (
    !a ||
    a.target ||
    a.hasAttribute("download") ||
    a.origin !== window.location.origin ||
    a.pathname.startsWith("/api/")
  ) {
    return;
  }
  e.preventDefault();
  navigate(a.pathname + a.search);
}

export function useRoute(): Route {
  const read = () => parseRoute(window.location.pathname, window.location.search);
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const update = () => setRoute(read());
    listeners.add(update);
    window.addEventListener("popstate", update);
    return () => {
      listeners.delete(update);
      window.removeEventListener("popstate", update);
    };
  }, []);
  return route;
}
