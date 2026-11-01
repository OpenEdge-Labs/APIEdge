// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// API keys of one product (T-008): list, create (the key is shown once) and revoke. Keys work
// for every API of the product that has an API key policy.
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { canProduct } from "../access";
import type { Me, Product } from "../types";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

interface ApiKey {
  id: number;
  name: string;
  prefix: string;
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export function ApiKeysPanel({ me, tenantId, product, onClose }: { me: Me; tenantId: number; product: Product; onClose: () => void }) {
  const base = `/tenants/${tenantId}/products/${product.id}/api-keys`;
  const keys = useLoad(() => api<ApiKey[]>(base), [base]);
  const action = useAction();
  const [name, setName] = useState("");
  const [expires, setExpires] = useState("");
  const [created, setCreated] = useState<{ name: string; key: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const manage = canProduct(me, "apikey:manage", product.id) && product.lifecycle !== "retired";

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    setCreated(null);
    const body: Record<string, unknown> = { name: name.trim() };
    if (expires) body.expires_at = new Date(`${expires}T23:59:59`).toISOString();
    await action.run(async () => {
      const out = await api<ApiKey & { key: string }>(base, { method: "POST", body });
      setCreated({ name: out.name, key: out.key });
      setName("");
      setExpires("");
      keys.reload();
    });
  };
  const revoke = async (k: ApiKey) => {
    if (!window.confirm(`Revoke the key "${k.name}" (${k.prefix}...)? Callers using it are refused at once.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${k.id}/revoke`, { method: "POST" }))) {
      setNotice(`Key "${k.name}" revoked.`);
      keys.reload();
    }
  };

  return (
    <Card title={`API keys of ${product.name}`} actions={<button onClick={onClose}>Close</button>}>
      <p className="hint">
        Keys work for every API of this product that has an API key policy. Send them in the configured header (default
        <code> x-api-key</code>). APIEdge stores only a hash: a key is shown once, when it is created.
      </p>
      <ErrorBox error={keys.error || action.error} />
      <Notice text={notice} />
      {created && (
        <div className="notice" role="status">
          <p>
            New key for <strong>{created.name}</strong>. Copy it now; it will not be shown again.
          </p>
          <code className="secret-once">{created.key}</code>{" "}
          <button type="button" onClick={() => void navigator.clipboard?.writeText(created.key)}>Copy</button>{" "}
          <button type="button" onClick={() => setCreated(null)}>Done</button>
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Key</th>
            <th>Status</th>
            <th>Created</th>
            <th>Expires</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {(keys.data ?? []).map((k) => (
            <tr key={k.id}>
              <td>{k.name}</td>
              <td><code>{k.prefix}...</code></td>
              <td><span className={`lifecycle ${k.status === "active" ? "published" : "retired"}`}>{k.status}</span></td>
              <td>{fmtDate(k.created_at)}</td>
              <td>{fmtDate(k.expires_at)}</td>
              <td className="actions">
                {manage && k.status !== "revoked" && (
                  <button className="danger" disabled={action.busy} onClick={() => void revoke(k)}>Revoke</button>
                )}
              </td>
            </tr>
          ))}
          {keys.data && keys.data.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">No keys yet.</td>
            </tr>
          )}
        </tbody>
      </table>
      {manage && (
        <form onSubmit={create} className="row">
          <Field label="Name" value={name} onChange={setName} placeholder="mobile app" required />
          <Field label="Expires (optional)" type="date" value={expires} onChange={setExpires} />
          <button type="submit" className="primary" disabled={action.busy || !name.trim()}>Create key</button>
        </form>
      )}
    </Card>
  );
}
