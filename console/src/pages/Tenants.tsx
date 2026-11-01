// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can } from "../access";
import type { Me, Tenant } from "../types";
import { Card, ErrorBox, Field, fmtDate, useAction, useLoad } from "../ui";

export function TenantsPage({ me, onChanged }: { me: Me; onChanged: () => void }) {
  const { data, error, reload } = useLoad(() => api<Tenant[]>("/tenants"), []);
  const action = useAction();
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  const [newName, setNewName] = useState("");

  const done = () => {
    reload();
    onChanged();
  };

  const create = async (e: FormEvent) => {
    e.preventDefault();
    if (await action.run(() => api("/tenants", { method: "POST", body: { slug, name } }))) {
      setSlug("");
      setName("");
      done();
    }
  };
  const patch = async (t: Tenant, body: { name?: string; is_active?: boolean }) => {
    if (await action.run(() => api(`/tenants/${t.id}`, { method: "PATCH", body }))) {
      setEditing(null);
      done();
    }
  };
  const remove = async (t: Tenant) => {
    if (!window.confirm(`Delete tenant "${t.name}" with all its users and roles? This cannot be undone.`)) return;
    if (await action.run(() => api(`/tenants/${t.id}`, { method: "DELETE" }))) done();
  };

  return (
    <>
      <Card title="Tenants">
        <ErrorBox error={error || action.error} />
        <table>
          <thead>
            <tr>
              <th>Slug</th>
              <th>Name</th>
              <th>Status</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((t) => (
              <tr key={t.id}>
                <td>{t.slug}</td>
                <td>
                  {editing === t.id ? (
                    <form
                      className="inline"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void patch(t, { name: newName });
                      }}
                    >
                      <input value={newName} onChange={(e) => setNewName(e.target.value)} aria-label="Tenant name" />
                      <button type="submit" disabled={action.busy}>Save</button>
                      <button type="button" onClick={() => setEditing(null)}>Cancel</button>
                    </form>
                  ) : (
                    t.name
                  )}
                </td>
                <td>{t.is_active ? "Active" : <span className="badge bad">Suspended</span>}</td>
                <td>{fmtDate(t.created_at)}</td>
                <td className="actions">
                  {can(me, "tenant:update") && editing !== t.id && (
                    <button
                      onClick={() => {
                        setEditing(t.id);
                        setNewName(t.name);
                      }}
                    >
                      Rename
                    </button>
                  )}
                  {me.is_superadmin && (
                    <button disabled={action.busy} onClick={() => void patch(t, { is_active: !t.is_active })}>
                      {t.is_active ? "Suspend" : "Activate"}
                    </button>
                  )}
                  {me.is_superadmin && (
                    <button className="danger" disabled={action.busy} onClick={() => void remove(t)}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.length === 0 && <p className="muted">No tenants yet.</p>}
      </Card>
      {me.is_superadmin && (
        <Card title="Create tenant">
          <form className="row" onSubmit={create}>
            <Field label="Slug (a-z, 0-9, -)" value={slug} onChange={setSlug} required />
            <Field label="Name" value={name} onChange={setName} required />
            <button type="submit" className="primary" disabled={action.busy}>Create</button>
          </form>
        </Card>
      )}
    </>
  );
}
