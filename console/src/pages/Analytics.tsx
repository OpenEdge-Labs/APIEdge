// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// Analytics dashboard (T-013): traffic, latency percentiles, error rate, status codes, top APIs
// and consumers for a time range, with drill-down filters and CSV export. The server limits the
// data to the products the user may view.
import { useState } from "react";
import { api, apiFile } from "../api";
import {
  RANGES,
  analyticsQuery,
  consumerLabel,
  fmtBytes,
  fmtCount,
  fmtMs,
  fmtPct,
  latencyLine,
  statusClass,
  trafficBars,
  type AnalyticsFilters,
} from "../analytics";
import type { AnalyticsPoint, AnalyticsSummary } from "../types";
import { Card, ErrorBox, useAction, useLoad } from "../ui";

const W = 720;
const H = 160;

export function AnalyticsPage({ tenantId }: { tenantId: number }) {
  const [filters, setFilters] = useState<AnalyticsFilters>({ range: "1h", apiId: null, consumer: null });
  const [apiName, setApiName] = useState<string>("");
  const [consumerInput, setConsumerInput] = useState("");
  const base = `/tenants/${tenantId}/analytics`;
  const { data, error, reload } = useLoad(
    () => api<AnalyticsSummary>(`${base}/summary?${analyticsQuery(filters, new Date())}`),
    [tenantId, filters],
  );
  const exporting = useAction();

  const exportCsv = () =>
    void exporting.run(async () => {
      const blob = await apiFile(`${base}/export.csv?${analyticsQuery(filters, new Date())}`, "text/csv");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `apiedge-analytics-${filters.range}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

  const set = (patch: Partial<AnalyticsFilters>) => setFilters((f) => ({ ...f, ...patch }));

  return (
    <Card
      title="Analytics"
      actions={
        <>
          <button onClick={reload}>Refresh</button>
          <button disabled={exporting.busy} onClick={exportCsv}>
            Export CSV
          </button>
        </>
      }
    >
      <div className="row">
        <label className="field">
          <span>Time range</span>
          <select value={filters.range} onChange={(e) => set({ range: e.target.value })}>
            {RANGES.map((r) => (
              <option key={r.key} value={r.key}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            const v = consumerInput.trim();
            set({ consumer: v === "" ? null : v });
          }}
        >
          <label className="field">
            <span>Consumer</span>
            <input value={consumerInput} maxLength={128} placeholder="any" onChange={(e) => setConsumerInput(e.target.value)} />
          </label>
          <button type="submit">Filter</button>
        </form>
      </div>
      {(filters.apiId !== null || filters.consumer !== null) && (
        <div className="chips">
          {filters.apiId !== null && (
            <span className="chip">
              API: {apiName || `#${filters.apiId}`}{" "}
              <button className="link" aria-label="Clear API filter" onClick={() => set({ apiId: null })}>
                x
              </button>
            </span>
          )}
          {filters.consumer !== null && (
            <span className="chip">
              Consumer: {consumerLabel(filters.consumer)}{" "}
              <button
                className="link"
                aria-label="Clear consumer filter"
                onClick={() => {
                  setConsumerInput("");
                  set({ consumer: null });
                }}
              >
                x
              </button>
            </span>
          )}
        </div>
      )}
      <ErrorBox error={error ?? exporting.error} />
      {data === undefined ? (
        !error && <p className="muted">Loading...</p>
      ) : (
        <Dashboard
          data={data}
          onApi={(id, name) => {
            setApiName(name);
            set({ apiId: id });
          }}
          onConsumer={(c) => {
            setConsumerInput(c);
            set({ consumer: c });
          }}
        />
      )}
    </Card>
  );
}

function Dashboard({
  data,
  onApi,
  onConsumer,
}: {
  data: AnalyticsSummary;
  onApi: (id: number, name: string) => void;
  onConsumer: (consumer: string) => void;
}) {
  const t = data.totals;
  const start = Math.floor(new Date(data.start).getTime() / 1000);
  const end = Math.floor(new Date(data.end).getTime() / 1000);
  return (
    <>
      <div className="kpis">
        <Kpi label="Requests" value={fmtCount(t.requests)} />
        <Kpi label="Error rate" value={fmtPct(t.error_rate)} cls={t.error_rate > 0.05 ? "bad" : ""} />
        <Kpi label="4xx / 5xx" value={`${fmtCount(t.client_errors)} / ${fmtCount(t.server_errors)}`} />
        <Kpi label="p50 latency" value={fmtMs(t.latency_p50_ms)} />
        <Kpi label="p95 latency" value={fmtMs(t.latency_p95_ms)} />
        <Kpi label="p99 latency" value={fmtMs(t.latency_p99_ms)} />
        <Kpi label="Data in / out" value={`${fmtBytes(t.bytes_in)} / ${fmtBytes(t.bytes_out)}`} />
      </div>
      {t.requests === 0 ? (
        <p className="muted">No gateway traffic in this time range.</p>
      ) : (
        <>
          <TrafficChart points={data.series} start={start} end={end} step={data.step_seconds} />
          <div className="split">
            <section>
              <h3>Top APIs</h3>
              <table>
                <thead>
                  <tr>
                    <th>API</th>
                    <th className="num">Requests</th>
                    <th className="num">Errors</th>
                    <th className="num">p95</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_apis.map((a) => (
                    <tr key={a.api_id}>
                      <td>
                        <button className="link" title="Filter by this API" onClick={() => onApi(a.api_id, a.name ?? `#${a.api_id}`)}>
                          {a.name ?? `API #${a.api_id} (deleted)`}
                        </button>
                      </td>
                      <td className="num">{fmtCount(a.requests)}</td>
                      <td className="num">{fmtPct(a.error_rate)}</td>
                      <td className="num">{fmtMs(a.latency_p95_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
            <section>
              <h3>Status codes</h3>
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th className="num">Requests</th>
                    <th className="num">Share</th>
                  </tr>
                </thead>
                <tbody>
                  {data.status_codes.map((s) => (
                    <tr key={s.status}>
                      <td className={statusClass(s.status)}>{s.status}</td>
                      <td className="num">{fmtCount(s.requests)}</td>
                      <td className="num">{fmtPct(s.requests / t.requests)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
            <section>
              <h3>Top consumers</h3>
              <table>
                <thead>
                  <tr>
                    <th>Consumer</th>
                    <th className="num">Requests</th>
                    <th className="num">Errors</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_consumers.map((c) => (
                    <tr key={c.consumer}>
                      <td>
                        <button className="link" title="Filter by this consumer" onClick={() => onConsumer(c.consumer)}>
                          {consumerLabel(c.consumer)}
                        </button>
                      </td>
                      <td className="num">{fmtCount(c.requests)}</td>
                      <td className="num">{fmtPct(c.error_rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          </div>
        </>
      )}
    </>
  );
}

function Kpi({ label, value, cls = "" }: { label: string; value: string; cls?: string }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${cls}`}>{value}</div>
    </div>
  );
}

function TrafficChart({ points, start, end, step }: { points: AnalyticsPoint[]; start: number; end: number; step: number }) {
  const bars = trafficBars(points, start, end, step, W, H);
  const maxLatency = Math.max(1, ...points.map((p) => p.latency_p95_ms ?? 0));
  const line = latencyLine(points, start, end, step, W, H, maxLatency);
  return (
    <>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Requests and p95 latency over time">
        {bars.map((b) => (
          <g key={b.t}>
            <title>{`${new Date(b.t * 1000).toLocaleString()}: ${b.requests} requests, ${b.errors} errors`}</title>
            <rect className="bar" x={b.x} y={H - b.height} width={b.width} height={b.height} />
            {b.errorHeight > 0 && <rect className="bar-err" x={b.x} y={H - b.errorHeight} width={b.width} height={b.errorHeight} />}
          </g>
        ))}
        {line && <polyline className="p95" points={line} />}
      </svg>
      <div className="legend">
        <i className="sw-req" />
        requests
        <i className="sw-err" />
        errors
        <i className="sw-p95" />
        p95 latency (max {fmtMs(maxLatency)}) - one bar per {step >= 3600 ? `${step / 3600} h` : `${step / 60} min`}
      </div>
    </>
  );
}
