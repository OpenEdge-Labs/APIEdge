// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can, grantable } from "../access";
import type { Me, Permission, Role } from "../types";
import { Card, ErrorBox, Field, useAction, useLoad } from "../ui";

export function RolesPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/roles`;
  const roles = useLoad(() => api<Role[]>(base), [tenantId]);
  const catalog = useLoad(() => api<Permission[]>("/permissions"), []);
  const action = useAction();
  const [editing, setEditing] = useState<Role | "new" | null>(null);
  const tenantPerms = (catalog.data ?? []).filter((p) => !p.platform_only);

  const remove = async (r: Role) => {
    if (!window.confirm(`Delete role "${r.name}"?`)) return;
    if (await action.run(() => api(`${base}/${r.id}`, { method: "DELETE" }))) roles.reload();
  };

  return (
    <>
      <Card
        title="Roles"
        actions={
          can(me, "role:create") && editing === null ? (
            <button className="primary" onClick={() => setEditing("new")}>New custom role</button>
          ) : undefined
        }
      >
        <ErrorBox error={roles.error || catalog.error || action.error} />
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Type</th>
              <th>Permissions</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(roles.data ?? []).map((r) => (
              <tr key={r.id}>
                <td>
                  <strong>{r.name}</strong>
                  {r.description && <div className="muted small">{r.description}</div>}
                </td>
                <td>{r.is_builtin ? "Built-in" : "Custom"}</td>
                <td className="perms">
                  {r.permissions.map((p) => (
                    <code key={p}>{p}</code>
                  ))}
                </td>
                <td className="actions">
                  {!r.is_builtin && can(me, "role:update") && (
                    <button onClick={() => setEditing(r)}>Edit</button>
                  )}
                  {!r.is_builtin && can(me, "role:delete") && (
                    <button className="danger" disabled={action.busy} onClick={() => void remove(r)}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {editing !== null && (
        <RoleEditor
          key={editing === "new" ? "new" : editing.id}
          me={me}
          base={base}
          role={editing === "new" ? null : editing}
          catalog={tenantPerms}
          onClose={(changed) => {
            setEditing(null);
            if (changed) roles.reload();
          }}
        />
      )}
      <Card title="Permission catalog">
        <table>
          <tbody>
            {(catalog.data ?? []).map((p) => (
              <tr key={p.name}>
                <td><code>{p.name}</code></td>
                <td>{p.description}</td>
                <td>{p.platform_only ? <span className="badge">platform</span> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}

function RoleEditor(props: { me: Me; base: string; role: Role | null; catalog: Permission[]; onClose: (changed: boolean) => void }) {
  const { role } = props;
  const [name, setName] = useState(role?.name ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [perms, setPerms] = useState<Set<string>>(new Set(role?.permissions ?? []));
  const action = useAction();
  const allowed = grantable(props.me, props.catalog.map((p) => p.name));

  const toggle = (p: string, on: boolean) => {
    const next = new Set(perms);
    if (on) next.add(p);
    else next.delete(p);
    setPerms(next);
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { name, description, permissions: [...perms].sort() };
    const ok = await action.run(() =>
      role ? api(`${props.base}/${role.id}`, { method: "PATCH", body }) : api(props.base, { method: "POST", body }),
    );
    if (ok) props.onClose(true);
  };

  return (
    <Card title={role ? `Edit role ${role.name}` : "New custom role"}>
      <form onSubmit={submit}>
        <div className="row">
          <Field label="Name" value={name} onChange={setName} required />
          <Field label="Description" value={description} onChange={setDescription} />
        </div>
        <fieldset className="checks perms-grid">
          <legend>Permissions (you can only include permissions you hold)</legend>
          {props.catalog.map((p) => (
            <label key={p.name} className="check" title={p.description}>
              <input
                type="checkbox"
                checked={perms.has(p.name)}
                disabled={!allowed.has(p.name)}
                onChange={(e) => toggle(p.name, e.target.checked)}
              />
              <code>{p.name}</code>
            </label>
          ))}
        </fieldset>
        <ErrorBox error={action.error} />
        <div className="row">
          <button type="submit" className="primary" disabled={action.busy}>Save</button>
          <button type="button" onClick={() => props.onClose(false)}>Cancel</button>
        </div>
      </form>
    </Card>
  );
}
