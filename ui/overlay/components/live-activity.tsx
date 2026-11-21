"use client";

import { useEffect, useState } from "react";

type RequestRow = {
  time: string;
  request_id: string;
  method: string;
  route: string;
  status: number;
  upstream: string;
  decision: string;
  rules: string[];
  signals: string[];
};

export function LiveActivity() {
  const [rows, setRows] = useState<RequestRow[] | null>(null);
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("");
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    async function refresh() {
      try {
        const response = await fetch("/activity.json", {
          cache: "no-store", signal: controller.signal,
        });
        if (!response.ok) throw new Error("Activity unavailable");
        const activity = await response.json();
        if (!Array.isArray(activity.rows)) throw new Error("Invalid activity response");
        if (!controller.signal.aborted) {
          setRows(activity.rows);
          setUnavailable(false);
        }
      } catch {
        if (!controller.signal.aborted) setUnavailable(true);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 2000);
      }
    }

    refresh();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, []);

  const search = query.trim().toLowerCase();
  const visible = (rows ?? []).filter(row =>
    (!decision || row.decision === decision) &&
    [row.request_id, row.route, row.method, row.status, ...row.rules, ...row.signals]
      .join(" ").toLowerCase().includes(search),
  );

  return <main>
    <div className="pagehead"><div className="wrap">
      <h1>Live activity</h1>
      <p>See recent requests from the VM gateway. Search for a request ID from your browser or terminal.</p>
    </div></div>
    <div className="wrap content">
      <div className="activity-filters">
        <label>Search requests
          <input type="search" value={query} onChange={event => setQuery(event.target.value)}
            placeholder="Request ID, route, status or rule" />
        </label>
        <label>Decision
          <select value={decision} onChange={event => setDecision(event.target.value)}>
            <option value="">All decisions</option>
            <option>Forwarded</option><option>WAF blocked</option>
            <option>Rate limited</option><option>Edge response</option>
          </select>
        </label>
      </div>
      {unavailable && <p role="alert">{rows ? "Connection lost. Showing the last received requests." : "The VM activity feed is unavailable."}</p>}
      {!rows && !unavailable && <p>Loading activity…</p>}
      {rows && <>
        <p className="activity-count">{visible.length} of {rows.length} recent requests shown. Refreshes every two seconds.</p>
        {visible.length > 0 ? <div className="scroll">
          <table className="activity-table">
            <thead><tr><th>Time</th><th>Request</th><th>HTTP</th><th>Upstream</th><th>Decision</th><th>Request ID</th></tr></thead>
            <tbody>{visible.map(row => <tr key={row.request_id}>
              <td>{row.time ? new Date(row.time).toLocaleTimeString() : "—"}</td>
              <td>{row.method} {row.route}</td>
              <td>{row.status}</td>
              <td>{row.upstream || "—"}</td>
              <td><strong>{row.decision}</strong>
                {row.signals.length > 0 && <div>{row.signals.join(", ")}</div>}
                {row.rules.length > 0 && <div>CRS {row.rules.join(", ")}</div>}
              </td>
              <td><code>{row.request_id}</code></td>
            </tr>)}</tbody>
          </table>
        </div> : <p>No recent requests match these filters.</p>}
      </>}
      <p className="activity-count">CRS signatures are rule matches. Interpret them alongside the request and the proxy decision.</p>
      <p className="activity-count"><a href="/evidence/">Open published test evidence →</a></p>
    </div>
  </main>;
}
