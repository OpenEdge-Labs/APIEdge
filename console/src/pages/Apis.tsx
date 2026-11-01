// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// APIs of one product (T-006): list, the no-code form editor (base path, version, upstreams,
// routes), lifecycle and delete. Buttons follow the caller's permissions for this product; the
// server checks every call itself.
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { canProduct } from "../access";
import { METHODS, emptyForm, formErrors, formFromApi, toBody, type ApiForm } from "../apis";
import { TRANSITIONS, deletable } from "../products";
import type { Api, HttpMethod, Lifecycle, Me, Product } from "../types";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

const VERB: Record<Lifecycle, string> = {
  draft: "Back to draft",
  published: "Publish",
  deprecated: "Deprecate",
  retired: "Retire",
};

export function ApisPanel({ me, tenantId, product, onClose }: { me: Me; tenantId: number; product: Product; onClose: () => void }) {
  const base = `/tenants/${tenantId}/products/${product.id}/apis`;
  const apis = useLoad(() => api<Api[]>(base), [base]);
  const action = useAction();
  const [editing, setEditing] = useState<Api | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const retiredProduct = product.lifecycle === "retired";
  const may = (permission: string) => canProduct(me, permission, product.id);

  const move = async (a: Api, to: Lifecycle) => {
    if (to === "retired" && !window.confirm(`Retire "${a.name}" ${a.version}? Retired APIs cannot be changed again.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${a.id}/lifecycle`, { method: "POST", body: { lifecycle: to } }))) {
      setNotice(`${a.name} ${a.version} is now ${to}.`);
      apis.reload();
    }
  };
  const remove = async (a: Api) => {
    if (!window.confirm(`Delete API "${a.name}" ${a.version}?`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${a.id}`, { method: "DELETE" }))) {
      if (editing?.id === a.id) setEditing(null);
      apis.reload();
    }
  };
  // In a retired product, APIs can only be wound down (deprecated, then retired).
  const moves = (a: Api) => TRANSITIONS[a.lifecycle].filter((to) => !retiredProduct || to === "deprecated" || to === "retired");

  return (
    <>
      <Card title={`APIs of ${product.name}`} actions={<button onClick={onClose}>Close</button>}>
        <ErrorBox error={apis.error || action.error} />
        <Notice text={notice} />
        <table>
          <thead>
            <tr>
              <th>API</th>
              <th>Base path</th>
              <th>Lifecycle</th>
              <th>Upstreams</th>
              <th>Routes</th>
              <th>Updated</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(apis.data ?? []).map((a) => (
              <tr key={a.id}>
                <td>
                  <strong>{a.name}</strong> <span className="badge">{a.version}</span>
                  {a.description && <div className="muted small">{a.description}</div>}
                </td>
                <td>
                  <code>{a.base_path}</code>
                  {(a.lifecycle === "published" || a.lifecycle === "deprecated") && (
                    <div className="muted small" title="Path on the gateway port">
                      Gateway: <code>{a.gateway_path}</code>
                    </div>
                  )}
                </td>
                <td><span className={`lifecycle ${a.lifecycle}`}>{a.lifecycle}</span></td>
                <td>{a.upstreams.length}</td>
                <td>{a.routes.length}</td>
                <td>{fmtDate(a.updated_at)}</td>
                <td className="actions">
                  <button onClick={() => setEditing(a)}>
                    {a.lifecycle !== "retired" && !retiredProduct && may("api:update") ? "Edit" : "View"}
                  </button>
                  {may("api:publish") &&
                    moves(a).map((to) => (
                      <button key={to} disabled={action.busy} onClick={() => void move(a, to)}>{VERB[to]}</button>
                    ))}
                  {deletable(a.lifecycle) && may("api:delete") && (
                    <button className="danger" disabled={action.busy} onClick={() => void remove(a)}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
            {apis.data && apis.data.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">No APIs in this product yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
      {editing && (
        <ApiEditor
          key={editing.id}
          base={base}
          api={editing}
          readOnly={editing.lifecycle === "retired" || retiredProduct || !may("api:update")}
          onDone={(changed) => {
            setEditing(null);
            if (changed) apis.reload();
          }}
        />
      )}
      {!editing && !retiredProduct && may("api:create") && (
        <ApiEditor key="new" base={base} api={null} readOnly={false} onDone={(changed) => changed && apis.reload()} />
      )}
    </>
  );
}

function ApiEditor(props: { base: string; api: Api | null; readOnly: boolean; onDone: (changed: boolean) => void }) {
  const { api: current, readOnly } = props;
  const [form, setForm] = useState<ApiForm>(current ? formFromApi(current) : emptyForm());
  const [problems, setProblems] = useState<string[]>([]);
  const action = useAction();
  const set = (patch: Partial<ApiForm>) => setForm((f) => ({ ...f, ...patch }));
  const baseLocked = current !== null && current.lifecycle !== "draft";

  const setUpstream = (i: number, patch: Partial<ApiForm["upstreams"][number]>) =>
    set({ upstreams: form.upstreams.map((u, j) => (j === i ? { ...u, ...patch } : u)) });
  const setRoute = (i: number, patch: Partial<ApiForm["routes"][number]>) =>
    set({ routes: form.routes.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  const toggleMethod = (i: number, m: HttpMethod) => {
    const methods = form.routes[i].methods;
    setRoute(i, { methods: methods.includes(m) ? methods.filter((x) => x !== m) : [...methods, m] });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errors = formErrors(form);
    setProblems(errors);
    if (errors.length) return;
    const body: Record<string, unknown> = toBody(form);
    if (baseLocked) delete body.base_path;
    const ok = await action.run(() =>
      current ? api(`${props.base}/${current.id}`, { method: "PATCH", body }) : api(props.base, { method: "POST", body }),
    );
    if (ok) {
      if (!current) setForm(emptyForm());
      props.onDone(true);
    }
  };

  const title = current ? `${readOnly ? "API" : "Edit API"} ${current.name} ${current.version}` : "New API";
  return (
    <Card title={title}>
      <form onSubmit={submit}>
        <fieldset className="plain" disabled={readOnly || action.busy}>
          <div className="row">
            <Field label="Name" value={form.name} onChange={(v) => set({ name: v })} required />
            <Field label="Version" value={form.version} onChange={(v) => set({ version: v })} required />
            <label className="field">
              <span>Base path</span>
              <input
                value={form.base_path}
                onChange={(e) => set({ base_path: e.target.value })}
                placeholder="/orders/v1"
                disabled={baseLocked}
                required
              />
            </label>
            <Field label="Timeout (ms)" value={form.timeout_ms} onChange={(v) => set({ timeout_ms: v })} inputMode="numeric" />
          </div>
          <label className="field wide">
            <span>Description</span>
            <textarea value={form.description} maxLength={2000} rows={2} onChange={(e) => set({ description: e.target.value })} />
          </label>
          {baseLocked && <p className="hint">The base path can only change while the API is a draft.</p>}

          <h3>Upstreams</h3>
          <p className="hint">Backend URLs (http or https). Traffic is shared by weight. Private and loopback addresses are blocked unless an administrator allows them.</p>
          <table className="editor">
            <thead>
              <tr>
                <th>URL</th>
                <th>Weight</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {form.upstreams.map((u, i) => (
                <tr key={i}>
                  <td>
                    <input aria-label={`Upstream ${i + 1} URL`} value={u.url} placeholder="https://backend.example.com/api" onChange={(e) => setUpstream(i, { url: e.target.value })} />
                  </td>
                  <td className="narrow">
                    <input aria-label={`Upstream ${i + 1} weight`} value={u.weight} inputMode="numeric" onChange={(e) => setUpstream(i, { weight: e.target.value })} />
                  </td>
                  <td className="actions">
                    <button type="button" onClick={() => set({ upstreams: form.upstreams.filter((_, j) => j !== i) })}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" onClick={() => set({ upstreams: [...form.upstreams, { url: "", weight: "1" }] })}>Add upstream</button>

          <h3>Routes</h3>
          <p className="hint">Paths are relative to the base path. Use {"{name}"} for a parameter and end with /* to match everything below a path.</p>
          <table className="editor">
            <thead>
              <tr>
                <th>Methods</th>
                <th>Path</th>
                <th>Description</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {form.routes.map((r, i) => (
                <tr key={i}>
                  <td>
                    {METHODS.map((m) => (
                      <label key={m} className="check">
                        <input type="checkbox" checked={r.methods.includes(m)} onChange={() => toggleMethod(i, m)} />
                        {m}
                      </label>
                    ))}
                  </td>
                  <td>
                    <input aria-label={`Route ${i + 1} path`} value={r.path} placeholder="/orders/{id}" onChange={(e) => setRoute(i, { path: e.target.value })} />
                  </td>
                  <td>
                    <input aria-label={`Route ${i + 1} description`} value={r.description} maxLength={2000} onChange={(e) => setRoute(i, { description: e.target.value })} />
                  </td>
                  <td className="actions">
                    <button type="button" onClick={() => set({ routes: form.routes.filter((_, j) => j !== i) })}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" onClick={() => set({ routes: [...form.routes, { methods: ["GET"], path: "", description: "" }] })}>Add route</button>
        </fieldset>

        {problems.length > 0 && (
          <ul className="error" role="alert">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        )}
        <ErrorBox error={action.error} />
        <p className="hint">New APIs start as drafts. Publishing needs at least one upstream and one route.</p>
        <div className="row">
          {!readOnly && (
            <button type="submit" className="primary" disabled={action.busy}>{current ? "Save" : "Create API"}</button>
          )}
          {current && <button type="button" onClick={() => props.onDone(false)}>{readOnly ? "Close" : "Cancel"}</button>}
        </div>
      </form>
    </Card>
  );
}
