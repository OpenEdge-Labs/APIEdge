// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Packet inspector (T-012): start and stop time-boxed captures, browse and filter captured
// exchanges (live via Server-Sent Events), inspect one with its policy-by-policy trace, export
// HAR and replay a request. Everything is masked unless the user holds inspector:unmask and asks
// for it (audited). The server enforces every permission; this page only hides what is not allowed.
import { useEffect, useRef, useState } from "react";
import { API_BASE, api, apiFile } from "../api";
import { canAnyProduct, canProduct } from "../access";
import { fmtMs, statusClass } from "../analytics";
import {
  EMPTY_FILTERS,
  bodyText,
  captureBody,
  captureErrors,
  exchangeQuery,
  mergeExchanges,
  remaining,
  type CaptureForm,
  type ExchangeFilters,
} from "../inspector";
import type { Api, CaptureSession, ExchangeDetail, ExchangeSummary, Me, Product, ReplayResult } from "../types";
import { Card, ErrorBox, fmtDate, useAction, useLoad } from "../ui";

const EMPTY_FORM: CaptureForm = {
  productId: null,
  apiId: null,
  route: "",
  consumer: "",
  duration: "15",
  maxExchanges: "200",
  maxBody: "16384",
  maskFields: "",
};

export function InspectorPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/inspector`;
  const sessions = useLoad(() => api<CaptureSession[]>(`${base}/sessions`), [tenantId]);
  const [filters, setFilters] = useState<ExchangeFilters>(EMPTY_FILTERS);
  const [rows, setRows] = useState<ExchangeSummary[]>([]);
  const [listError, setListError] = useState<unknown>(null);
  const [live, setLive] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const canCapture = canAnyProduct(me, "inspector:capture");

  const loadRows = () => {
    setListError(null);
    api<ExchangeSummary[]>(`${base}/exchanges?${exchangeQuery(filters, { limit: 100 })}`)
      .then(setRows)
      .catch(setListError);
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(loadRows, [tenantId, filters]);

  // Live view: new exchanges arrive as SSE events; the server ends each stream after a few
  // minutes and the browser reconnects (Last-Event-ID resumes where it stopped).
  const newest = useRef(0);
  newest.current = rows[0]?.id ?? newest.current;
  useEffect(() => {
    if (!live) return;
    let source: EventSource | null = null;
    let timer: number | undefined;
    let stopped = false;
    const open = () => {
      const q = exchangeQuery(filters, { after_id: newest.current });
      source = new EventSource(`${API_BASE}${base}/exchanges/stream?${q}`, { withCredentials: true });
      source.addEventListener("exchange", (ev) => {
        const row = JSON.parse((ev as MessageEvent<string>).data) as ExchangeSummary;
        setRows((cur) => mergeExchanges(cur, [row]));
      });
      source.onerror = () => {
        if (source?.readyState === EventSource.CLOSED && !stopped) {
          // Typically an expired access token: renew the session, then reconnect.
          source.close();
          timer = window.setTimeout(() => {
            void api("/auth/me").finally(() => {
              if (!stopped) open();
            });
          }, 2000);
        }
      };
    };
    open();
    return () => {
      stopped = true;
      source?.close();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [live, filters, base]);

  const sessionList = sessions.data ?? [];
  return (
    <>
      <Card title="Packet inspector" actions={<button onClick={sessions.reload}>Refresh</button>}>
        <p className="muted small">
          Capture is opt-in per API and stops automatically. Credentials and configured fields are masked.
        </p>
        <ErrorBox error={sessions.error} />
        {canCapture && <StartCapture me={me} tenantId={tenantId} onStarted={sessions.reload} />}
        <SessionTable
          me={me}
          base={base}
          sessions={sessionList}
          onChanged={() => {
            sessions.reload();
            loadRows();
          }}
          onShow={(id) => setFilters({ ...EMPTY_FILTERS, sessionId: id })}
        />
      </Card>
      <Card
        title="Captured exchanges"
        actions={
          <>
            <label className="check">
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live
            </label>
            <button onClick={loadRows}>Refresh</button>
          </>
        }
      >
        <ExchangeFilterBar sessions={sessionList} filters={filters} onChange={setFilters} />
        <ErrorBox error={listError} />
        {rows.length === 0 ? (
          <p className="muted">No captured exchanges match. Start a capture and send traffic through the gateway.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Path</th>
                <th>Status</th>
                <th className="num">Duration</th>
                <th>Consumer</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={r.id === selected ? "selected" : ""}>
                  <td>{fmtDate(r.started_at)}</td>
                  <td>{r.method}</td>
                  <td>
                    <button className="link" onClick={() => setSelected(r.id)}>
                      {r.path}
                    </button>
                  </td>
                  <td className={statusClass(r.status)}>{r.status}</td>
                  <td className="num">{fmtMs(r.duration_ms)}</td>
                  <td>{r.consumer || "(anonymous)"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {selected !== null && <ExchangePane key={selected} me={me} base={base} id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function StartCapture({ me, tenantId, onStarted }: { me: Me; tenantId: number; onStarted: () => void }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<CaptureForm>(EMPTY_FORM);
  const action = useAction();
  const products = useLoad(
    () => (open ? api<Product[]>(`/tenants/${tenantId}/products`) : Promise.resolve([] as Product[])),
    [tenantId, open],
  );
  const apis = useLoad(
    () =>
      form.productId === null
        ? Promise.resolve([] as Api[])
        : api<Api[]>(`/tenants/${tenantId}/products/${form.productId}/apis`),
    [tenantId, form.productId],
  );
  const allowed = (products.data ?? []).filter((p) => canProduct(me, "inspector:capture", p.id));
  const chosen = (apis.data ?? []).find((a) => a.id === form.apiId);
  const errors = captureErrors(form);
  const set = (patch: Partial<CaptureForm>) => setForm((f) => ({ ...f, ...patch }));

  if (!open) return <button onClick={() => setOpen(true)}>New capture</button>;
  return (
    <form
      className="card"
      onSubmit={(e) => {
        e.preventDefault();
        if (errors.length) return;
        void action
          .run(async () => {
            await api(`/tenants/${tenantId}/inspector/sessions`, { method: "POST", body: captureBody(form) });
          })
          .then((ok) => {
            if (ok) {
              setOpen(false);
              setForm(EMPTY_FORM);
              onStarted();
            }
          });
      }}
    >
      <div className="row">
        <label className="field">
          <span>Product</span>
          <select
            value={form.productId ?? ""}
            onChange={(e) => set({ productId: e.target.value ? Number(e.target.value) : null, apiId: null, route: "" })}
          >
            <option value="">Choose...</option>
            {allowed.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>API</span>
          <select value={form.apiId ?? ""} onChange={(e) => set({ apiId: e.target.value ? Number(e.target.value) : null, route: "" })}>
            <option value="">Choose...</option>
            {(apis.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} {a.version} ({a.gateway_path})
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Route</span>
          <select value={form.route} onChange={(e) => set({ route: e.target.value })}>
            <option value="">All routes</option>
            {(chosen?.routes ?? []).map((r) => (
              <option key={r.path} value={r.path}>
                {r.methods.join(",")} {r.path}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Consumer</span>
          <input value={form.consumer} maxLength={128} placeholder="any (e.g. key:mobile)" onChange={(e) => set({ consumer: e.target.value })} />
        </label>
      </div>
      <div className="row">
        <label className="field">
          <span>Duration (minutes)</span>
          <input inputMode="numeric" value={form.duration} onChange={(e) => set({ duration: e.target.value })} />
        </label>
        <label className="field">
          <span>Keep newest (exchanges)</span>
          <input inputMode="numeric" value={form.maxExchanges} onChange={(e) => set({ maxExchanges: e.target.value })} />
        </label>
        <label className="field">
          <span>Max body bytes</span>
          <input inputMode="numeric" value={form.maxBody} onChange={(e) => set({ maxBody: e.target.value })} />
        </label>
        <label className="field">
          <span>Extra fields to mask</span>
          <input value={form.maskFields} placeholder="ssn, card_number" onChange={(e) => set({ maskFields: e.target.value })} />
        </label>
      </div>
      {form.apiId !== null && errors.length > 0 && <p className="error">{errors.join(" ")}</p>}
      <ErrorBox error={action.error ?? products.error ?? apis.error} />
      <div className="row">
        <button type="submit" disabled={action.busy || errors.length > 0}>
          Start capture
        </button>
        <button type="button" className="link" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function SessionTable(props: {
  me: Me;
  base: string;
  sessions: CaptureSession[];
  onChanged: () => void;
  onShow: (id: number) => void;
}) {
  const { me, base, sessions } = props;
  const action = useAction();
  const now = new Date();
  if (sessions.length === 0) return <p className="muted">No captures yet.</p>;

  const download = (s: CaptureSession, unmasked: boolean) =>
    void action.run(async () => {
      const blob = await apiFile(`${base}/sessions/${s.id}/har${unmasked ? "?unmasked=true" : ""}`, "application/json");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `apiedge-capture-${s.id}.har`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

  return (
    <>
      <ErrorBox error={action.error} />
      <table>
        <thead>
          <tr>
            <th>API</th>
            <th>Scope</th>
            <th>State</th>
            <th className="num">Captured</th>
            <th>Started</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const capture = canProduct(me, "inspector:capture", s.product_id);
            return (
              <tr key={s.id}>
                <td>{s.api_name ?? `#${s.api_id}`}</td>
                <td className="small">
                  {s.route ?? "all routes"}, {s.consumer === null ? "any consumer" : s.consumer || "(anonymous)"}
                  {s.mask_fields.length > 0 && <> - masks {s.mask_fields.join(", ")}</>}
                </td>
                <td>{remaining(s, now)}</td>
                <td className="num">
                  {s.stored} / {s.captured}
                </td>
                <td className="small">
                  {fmtDate(s.created_at)} {s.created_by && `by ${s.created_by}`}
                </td>
                <td>
                  <button className="link" onClick={() => props.onShow(s.id)}>
                    Show
                  </button>{" "}
                  <button className="link" disabled={action.busy} onClick={() => download(s, false)}>
                    HAR
                  </button>
                  {canProduct(me, "inspector:unmask", s.product_id) && (
                    <>
                      {" "}
                      <button className="link" disabled={action.busy} onClick={() => download(s, true)}>
                        HAR (unmasked)
                      </button>
                    </>
                  )}
                  {capture && s.state === "active" && (
                    <>
                      {" "}
                      <button
                        className="link"
                        disabled={action.busy}
                        onClick={() =>
                          void action
                            .run(async () => {
                              await api(`${base}/sessions/${s.id}/stop`, { method: "POST" });
                            })
                            .then(props.onChanged)
                        }
                      >
                        Stop
                      </button>
                    </>
                  )}
                  {capture && (
                    <>
                      {" "}
                      <button
                        className="link"
                        disabled={action.busy}
                        onClick={() => {
                          if (!window.confirm("Delete this capture and all its exchanges?")) return;
                          void action
                            .run(async () => {
                              await api(`${base}/sessions/${s.id}`, { method: "DELETE" });
                            })
                            .then(props.onChanged);
                        }}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}

function ExchangeFilterBar(props: { sessions: CaptureSession[]; filters: ExchangeFilters; onChange: (f: ExchangeFilters) => void }) {
  const [draft, setDraft] = useState(props.filters);
  useEffect(() => setDraft(props.filters), [props.filters]);
  return (
    <form
      className="row"
      onSubmit={(e) => {
        e.preventDefault();
        props.onChange(draft);
      }}
    >
      <label className="field">
        <span>Capture</span>
        <select value={draft.sessionId ?? ""} onChange={(e) => setDraft({ ...draft, sessionId: e.target.value ? Number(e.target.value) : null })}>
          <option value="">All</option>
          {props.sessions.map((s) => (
            <option key={s.id} value={s.id}>
              #{s.id} {s.api_name ?? ""}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Method</span>
        <input value={draft.method} maxLength={10} placeholder="any" onChange={(e) => setDraft({ ...draft, method: e.target.value })} />
      </label>
      <label className="field">
        <span>Status</span>
        <select value={draft.statusClass ?? ""} onChange={(e) => setDraft({ ...draft, statusClass: e.target.value ? Number(e.target.value) : null })}>
          <option value="">any</option>
          {[2, 3, 4, 5].map((c) => (
            <option key={c} value={c}>
              {c}xx
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Path contains</span>
        <input value={draft.path} maxLength={200} onChange={(e) => setDraft({ ...draft, path: e.target.value })} />
      </label>
      <label className="field">
        <span>Consumer</span>
        <input value={draft.consumer} maxLength={128} placeholder="any" onChange={(e) => setDraft({ ...draft, consumer: e.target.value })} />
      </label>
      <button type="submit">Filter</button>
    </form>
  );
}

function Headers({ items }: { items: [string, string][] }) {
  if (items.length === 0) return <p className="muted small">(none)</p>;
  return (
    <table className="small">
      <tbody>
        {items.map(([k, v], i) => (
          <tr key={`${k}-${i}`}>
            <th>{k}</th>
            <td className="mono">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ExchangePane({ me, base, id, onClose }: { me: Me; base: string; id: number; onClose: () => void }) {
  const [unmasked, setUnmasked] = useState(false);
  const detail = useLoad(() => api<ExchangeDetail>(`${base}/exchanges/${id}${unmasked ? "?unmasked=true" : ""}`), [id, unmasked]);
  const [replay, setReplay] = useState<ReplayResult | null>(null);
  const replaying = useAction();
  const d = detail.data;
  const ex = d?.exchange;
  return (
    <Card
      title={d ? `${d.method} ${d.path}` : "Exchange"}
      actions={
        <>
          {d && canProduct(me, "inspector:unmask", d.product_id) && (
            <button onClick={() => setUnmasked((u) => !u)}>{unmasked ? "Mask" : "Show unmasked"}</button>
          )}
          {d && canProduct(me, "inspector:capture", d.product_id) && ex?.request.upstream_headers && (
            <button
              disabled={replaying.busy}
              onClick={() =>
                void replaying.run(async () => {
                  setReplay(await api<ReplayResult>(`${base}/exchanges/${id}/replay${unmasked ? "?unmasked=true" : ""}`, { method: "POST" }));
                })
              }
            >
              Replay
            </button>
          )}
          <button className="link" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <ErrorBox error={detail.error ?? replaying.error} />
      {d && ex && (
        <>
          {!d.masked && <p className="notice">Unmasked view (recorded in the audit log).</p>}
          <dl className="kv small">
            <dt>Request id</dt>
            <dd className="mono">{d.request_id}</dd>
            <dt>Status</dt>
            <dd className={statusClass(d.status)}>
              {d.status} (answered by {ex.response.source})
            </dd>
            <dt>Timings</dt>
            <dd>
              total {fmtMs(ex.timings.total_ms)}, upstream {fmtMs(ex.timings.upstream_ms)}, policies {fmtMs(ex.timings.policies_ms)}
            </dd>
            <dt>Upstream</dt>
            <dd className="mono">{ex.upstream ? `${ex.upstream} (attempt ${ex.upstream_attempts})` : "-"}</dd>
            <dt>Route / consumer / client</dt>
            <dd>
              {ex.route} / {ex.consumer || "(anonymous)"} / {ex.client_ip}
            </dd>
          </dl>
          <h3>Policy trace</h3>
          {ex.trace.length === 0 ? (
            <p className="muted small">No policies ran.</p>
          ) : (
            <table className="small">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Phase</th>
                  <th>Outcome</th>
                  <th>Detail</th>
                  <th className="num">Time</th>
                </tr>
              </thead>
              <tbody>
                {ex.trace.map((t, i) => (
                  <tr key={i}>
                    <td>
                      {t.type} <span className="muted">({t.policy_id})</span>
                    </td>
                    <td>{t.phase}</td>
                    <td className={t.outcome === "reject" || t.outcome === "error" ? "bad" : ""}>{t.outcome}</td>
                    <td>{t.detail}</td>
                    <td className="num">{fmtMs(t.duration_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="split">
            <div>
              <h3>Request</h3>
              <p className="mono small">
                {ex.request.method} {ex.request.url}
              </p>
              <Headers items={ex.request.headers} />
              <pre className="body">{bodyText(ex.request.body)}</pre>
            </div>
            <div>
              <h3>Response</h3>
              <p className="mono small">{ex.response.status}</p>
              <Headers items={ex.response.headers} />
              <pre className="body">{bodyText(ex.response.body)}</pre>
            </div>
          </div>
        </>
      )}
      {replay && (
        <>
          <h3>Replay result</h3>
          {replay.error ? (
            <p className="error">{replay.error}</p>
          ) : (
            <>
              <p className="small">
                <span className={statusClass(replay.status ?? 0)}>{replay.status}</span> in {fmtMs(replay.duration_ms)} from{" "}
                <span className="mono">{replay.url}</span>
              </p>
              <Headers items={replay.headers} />
              <pre className="body">{bodyText(replay.body)}</pre>
            </>
          )}
        </>
      )}
    </Card>
  );
}
