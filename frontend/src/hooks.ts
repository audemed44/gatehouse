import { useCallback, useEffect, useRef, useState } from "preact/hooks";

/**
 * Loads data and reloads it every `interval` ms while the tab is visible
 * (0 loads once). `reload` refreshes on demand.
 */
export function useData<T>(load: () => Promise<T>, interval = 0, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const loadRef = useRef(load);
  loadRef.current = load;
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const n = ++seq.current;
    try {
      const d = await loadRef.current();
      if (n === seq.current) {
        setData(d);
        setError("");
      }
    } catch (e) {
      if (n === seq.current) setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    setData(null);
    reload();
    if (!interval) return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") reload();
    }, interval);
    return () => {
      clearInterval(timer);
      seq.current++;
    };
  }, deps);

  return { data, error, reload, setData };
}

/** Warns before leaving the page while there are unsaved changes. */
export function useUnsavedWarning(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
}
