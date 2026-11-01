// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Product management (T-005): list, create, edit, lifecycle and delete; the APIs of a product
// open in the API panel (T-006). Buttons follow the
// caller's tenant-wide and product-scoped permissions; the server checks every call itself.
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can, canProduct } from "../access";
import { ApisPanel } from "./Apis";
import { TRANSITIONS, deletable, parseOwners } from "../products";
import type { Lifecycle, Me, Product, User } from "../types";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

const LIFECYCLES: Lifecycle[] = ["draft", "published", "deprecated", "retired"];
const VERB: Record<Lifecycle, string> = {
  draft: "Back to draft",
  published: "Publish",
  deprecated: "Deprecate",
  retired: "Retire",
};

export function ProductsPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/products`;
  const [filter, setFilter] = useState<Lifecycle | "">("");
  const products = useLoad(() => api<Product[]>(filter ? `${base}?lifecycle=${filter}` : base), [base, filter]);
  // Usernames for the owner picker, only when the caller may list users.
  const users = useLoad(
    () => (can(me, "user:read") ? api<User[]>(`/tenants/${tenantId}/users`) : Promise.resolve([] as User[])),
    [tenantId],
  );
  const action = useAction();
  const [editing, setEditing] = useState<Product | null>(null);
  const [apisOf, setApisOf] = useState<Product | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const move = async (p: Product, to: Lifecycle) => {
    if (to === "retired" && !window.confirm(`Retire "${p.name}"? Retired products cannot be changed again.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${p.id}/lifecycle`, { method: "POST", body: { lifecycle: to } }))) {
      setNotice(`${p.name} is now ${to}.`);
      products.reload();
    }
  };
  const remove = async (p: Product) => {
    if (!window.confirm(`Delete product "${p.name}"? Role grants scoped to it are revoked. Products that still contain APIs cannot be deleted.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${p.id}`, { method: "DELETE" }))) {
      if (editing?.id === p.id) setEditing(null);
      if (apisOf?.id === p.id) setApisOf(null);
      products.reload();
    }
  };

  return (
    <>
      <Card
        title="Products"
        actions={
          <label className="field inline">
            <span>Lifecycle</span>
            <select value={filter} onChange={(e) => setFilter(e.target.value as Lifecycle | "")}>
              <option value="">All</option>
              {LIFECYCLES.map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </label>
        }
      >
        <ErrorBox error={products.error || action.error} />
        <Notice text={notice} />
        <table>
          <thead>
            <tr>
              <th>Product</th>
              <th>Lifecycle</th>
              <th>Owners</th>
              <th>Updated</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(products.data ?? []).map((p) => (
              <tr key={p.id}>
                <td>
                  <strong>{p.name}</strong>
                  {p.description && <div className="muted small">{p.description}</div>}
                </td>
                <td><span className={`lifecycle ${p.lifecycle}`}>{p.lifecycle}</span></td>
                <td>{p.owners.map((o) => o.username).join(", ") || <span className="muted">-</span>}</td>
                <td>{fmtDate(p.updated_at)}</td>
                <td className="actions">
                  {canProduct(me, "api:read", p.id) && (
                    <button onClick={() => setApisOf(p)} aria-pressed={apisOf?.id === p.id}>APIs</button>
                  )}
                  {p.lifecycle !== "retired" && canProduct(me, "product:update", p.id) && (
                    <button onClick={() => setEditing(p)}>Edit</button>
                  )}
                  {canProduct(me, "product:publish", p.id) &&
                    TRANSITIONS[p.lifecycle].map((to) => (
                      <button key={to} disabled={action.busy} onClick={() => void move(p, to)}>{VERB[to]}</button>
                    ))}
                  {deletable(p.lifecycle) && canProduct(me, "product:delete", p.id) && (
                    <button className="danger" disabled={action.busy} onClick={() => void remove(p)}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
            {products.data && products.data.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">No products.</td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
      {apisOf && (
        <ApisPanel
          key={apisOf.id}
          me={me}
          tenantId={tenantId}
          product={(products.data ?? []).find((p) => p.id === apisOf.id) ?? apisOf}
          onClose={() => setApisOf(null)}
        />
      )}
      {editing && (
        <ProductForm
          key={editing.id}
          base={base}
          product={editing}
          usernames={(users.data ?? []).map((u) => u.username)}
          onDone={(changed) => {
            setEditing(null);
            if (changed) products.reload();
          }}
        />
      )}
      {can(me, "product:create") && !editing && !apisOf && (
        <ProductForm
          key="new"
          base={base}
          product={null}
          defaultOwners={me.tenant_id === tenantId ? me.username : ""}
          usernames={(users.data ?? []).map((u) => u.username)}
          onDone={(changed) => {
            if (changed) products.reload();
          }}
        />
      )}
    </>
  );
}

function ProductForm(props: {
  base: string;
  product: Product | null;
  defaultOwners?: string;
  usernames: string[];
  onDone: (changed: boolean) => void;
}) {
  const { product } = props;
  const [name, setName] = useState(product?.name ?? "");
  const [description, setDescription] = useState(product?.description ?? "");
  const [owners, setOwners] = useState(product ? product.owners.map((o) => o.username).join(", ") : (props.defaultOwners ?? ""));
  const action = useAction();
  const listId = product ? `owners-${product.id}` : "owners-new";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { name, description, owners: parseOwners(owners) };
    const ok = await action.run(() =>
      product ? api(`${props.base}/${product.id}`, { method: "PATCH", body }) : api(props.base, { method: "POST", body }),
    );
    if (ok) {
      if (!product) {
        setName("");
        setDescription("");
      }
      props.onDone(true);
    }
  };

  return (
    <Card title={product ? `Edit product ${product.name}` : "New product"}>
      <form onSubmit={submit}>
        <div className="row">
          <Field label="Name" value={name} onChange={setName} required />
          <label className="field">
            <span>Owners (usernames, comma separated)</span>
            <input value={owners} onChange={(e) => setOwners(e.target.value)} list={listId} autoComplete="off" />
            <datalist id={listId}>
              {props.usernames.map((u) => (
                <option key={u} value={u} />
              ))}
            </datalist>
          </label>
        </div>
        <label className="field wide">
          <span>Description</span>
          <textarea value={description} maxLength={2000} rows={3} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <p className="hint">New products start as drafts. Owners are contacts; access comes from role grants.</p>
        <ErrorBox error={action.error} />
        <div className="row">
          <button type="submit" className="primary" disabled={action.busy}>{product ? "Save" : "Create product"}</button>
          {product && <button type="button" onClick={() => props.onDone(false)}>Cancel</button>}
        </div>
      </form>
    </Card>
  );
}
