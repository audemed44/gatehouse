import { useState } from "preact/hooks";
import { api } from "../api";
import { useData } from "../hooks";
import { bytes, clock, statusTone } from "../lib";
import { navigate } from "../router";
import { Empty, ErrorNote, SectionHead } from "./ui";

export function LogsPage(props: { host: string }) {
  const [errors, setErrors] = useState(false);
  const { data, error } = useData(() => api.logs(props.host, errors), 5_000, [props.host, errors]);
  const hosts = (data?.stats ?? [])
    .filter((s) => s.host)
    .map((s) => s.host)
    .sort();

  return (
    <div class="page">
      <header class="page-head">
        <div class="eyebrow eyebrow-accent">Recent requests · kept in memory</div>
        <h1 class="page-title page-title-small">Logs</h1>
      </header>
      <div class="toolbar">
        <select
          class="input log-host"
          value={props.host}
          onChange={(e) => {
            const h = e.currentTarget.value;
            navigate(h ? `/logs?host=${encodeURIComponent(h)}` : "/logs", true);
          }}
        >
          <option value="">Every host</option>
          {props.host && !hosts.includes(props.host) && (
            <option value={props.host}>{props.host}</option>
          )}
          {hosts.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
        <div class="seg" role="group" aria-label="Show">
          <button class={errors ? "" : "active"} onClick={() => setErrors(false)}>
            All
          </button>
          <button class={errors ? "active" : ""} onClick={() => setErrors(true)}>
            Errors
          </button>
        </div>
      </div>
      {error && <ErrorNote>{error}</ErrorNote>}
      <section class="section">
        <SectionHead title={props.host || "Every host"}>
          <span class="eyebrow">Newest first · query strings left out</span>
        </SectionHead>
        {!data ? (
          <div class="skeleton list-skeleton" />
        ) : data.entries.length === 0 ? (
          <Empty>No requests yet.</Empty>
        ) : (
          <div class="table-wrap">
            <table class="table log-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Status</th>
                  {!props.host && <th>Host</th>}
                  <th>Request</th>
                  <th class="num">Size</th>
                  <th class="num">Time</th>
                  <th>Client</th>
                </tr>
              </thead>
              <tbody>
                {data.entries.map((e, i) => (
                  <tr key={i} class={e.matched ? "" : "muted"}>
                    <td class="mono">{clock(e.time)}</td>
                    <td
                      class={`mono tone-${e.asleep ? "accent" : statusTone(e.status)}`}
                      title={e.asleep ? "A monitor's probe; the app is asleep" : undefined}
                    >
                      {e.asleep ? "asleep" : e.status}
                    </td>
                    {!props.host && (
                      <td>
                        <a class="link" href={`/logs?host=${encodeURIComponent(e.host)}`}>
                          {e.host}
                        </a>
                        {!e.matched && <span class="chip">unknown</span>}
                      </td>
                    )}
                    <td class="mono log-path" title={e.path}>
                      <span class="muted">{e.method}</span> {e.path}
                    </td>
                    <td class="num mono">{bytes(e.bytes)}</td>
                    <td class="num mono">{e.ms} ms</td>
                    <td class="mono muted">
                      {e.client}
                      {e.tls ? "" : " · http"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
