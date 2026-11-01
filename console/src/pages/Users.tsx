// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can } from "../access";
import { PASSWORD_HINT } from "../auth";
import type { Assignment, Me, Product, Role, User } from "../types";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

export function UsersPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/users`;
  const users = useLoad(() => api<User[]>(base), [tenantId]);
  const canRoles = can(me, "role:read");
  const roles = useLoad(() => (canRoles ? api<Role[]>(`/tenants/${tenantId}/roles`) : Promise.resolve([])), [tenantId, canRoles]);
  const [open, setOpen] = useState<number | null>(null);
  const action = useAction();
  const [notice, setNotice] = useState<string | null>(null);

  const patch = async (u: User, body: Record<string, unknown>, msg: string) => {
    setNotice(null);
    if (await action.run(() => api(`${base}/${u.id}`, { method: "PATCH", body }))) {
      setNotice(msg);
      users.reload();
    }
  };
  const remove = async (u: User) => {
    if (!window.confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    if (await action.run(() => api(`${base}/${u.id}`, { method: "DELETE" }))) {
      setNotice(`Deleted ${u.username}.`);
      users.reload();
    }
  };

  return (
    <>
      <Card title="Users">
        <ErrorBox error={users.error || action.error} />
        <Notice text={notice} />
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Status</th>
              <th>MFA</th>
              <th>Last sign-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(users.data ?? []).map((u) => (
              <UserRow
                key={u.id}
                u={u}
                me={me}
                busy={action.busy}
                open={open === u.id}
                onToggle={() => setOpen(open === u.id ? null : u.id)}
                onPatch={patch}
                onDelete={remove}
                tenantId={tenantId}
                roles={roles.data ?? []}
              />
            ))}
          </tbody>
        </table>
      </Card>
      {can(me, "user:create") && (
        <CreateUser
          tenantId={tenantId}
          roles={can(me, "role:assign") ? (roles.data ?? []) : []}
          onCreated={(name) => {
            setNotice(`Created ${name}.`);
            users.reload();
          }}
        />
      )}
    </>
  );
}

function UserRow(props: {
  u: User;
  me: Me;
  busy: boolean;
  open: boolean;
  tenantId: number;
  roles: Role[];
  onToggle: () => void;
  onPatch: (u: User, body: Record<string, unknown>, msg: string) => Promise<void>;
  onDelete: (u: User) => Promise<void>;
}) {
  const { u, me, busy } = props;
  const self = u.id === me.id;
  const canUpdate = can(me, "user:update");
  const status = !u.is_active ? "Disabled" : u.is_locked ? "Locked" : u.must_change_password ? "Must change password" : "Active";
  return (
    <>
      <tr>
        <td>{u.username}{self && <span className="badge">you</span>}</td>
        <td>{u.email ?? "-"}</td>
        <td>{status}</td>
        <td>{u.mfa_enabled ? "On" : "Off"}</td>
        <td>{fmtDate(u.last_login_at)}</td>
        <td className="actions">
          {canUpdate && !self && (
            <button disabled={busy} onClick={() => void props.onPatch(u, { is_active: !u.is_active }, `${u.is_active ? "Disabled" : "Enabled"} ${u.username}.`)}>
              {u.is_active ? "Disable" : "Enable"}
            </button>
          )}
          {canUpdate && u.is_locked && (
            <button disabled={busy} onClick={() => void props.onPatch(u, { unlock: true }, `Unlocked ${u.username}.`)}>Unlock</button>
          )}
          {canUpdate && u.mfa_enabled && !self && (
            <button disabled={busy} onClick={() => void props.onPatch(u, { reset_mfa: true }, `Reset MFA for ${u.username}.`)}>Reset MFA</button>
          )}
          {(canUpdate || can(me, "role:read")) && (
            <button onClick={props.onToggle} aria-expanded={props.open}>{props.open ? "Close" : "Manage"}</button>
          )}
          {can(me, "user:delete") && !self && (
            <button className="danger" disabled={busy} onClick={() => void props.onDelete(u)}>Delete</button>
          )}
        </td>
      </tr>
      {props.open && (
        <tr className="detail">
          <td colSpan={6}>
            {canUpdate && !self && <ResetPassword tenantId={props.tenantId} user={u} />}
            {can(me, "role:read") && <Grants me={me} tenantId={props.tenantId} user={u} roles={props.roles} />}
          </td>
        </tr>
      )}
    </>
  );
}

function ResetPassword({ tenantId, user }: { tenantId: number; user: User }) {
  const [pw, setPw] = useState("");
  const action = useAction();
  const [notice, setNotice] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    if (await action.run(() => api(`/tenants/${tenantId}/users/${user.id}/reset-password`, { method: "POST", body: { new_password: pw } }))) {
      setPw("");
      setNotice("Password reset. The user must change it at next sign-in; their sessions have ended.");
    }
  };
  return (
    <form className="row" onSubmit={submit}>
      <Field label={`New password for ${user.username}`} type="password" value={pw} onChange={setPw} autoComplete="new-password" required />
      <button type="submit" disabled={action.busy}>Reset password</button>
      <ErrorBox error={action.error} />
      <Notice text={notice} />
    </form>
  );
}

function Grants({ me, tenantId, user, roles }: { me: Me; tenantId: number; user: User; roles: Role[] }) {
  const path = `/tenants/${tenantId}/users/${user.id}/roles`;
  const grants = useLoad(() => api<Assignment[]>(path), [path]);
  const action = useAction();
  const [roleId, setRoleId] = useState("");
  const [productId, setProductId] = useState("");
  const canAssign = can(me, "role:assign");
  // Products for product-scoped grants (T-005), when the caller may list them all.
  const products = useLoad(
    () => (can(me, "product:read") ? api<Product[]>(`/tenants/${tenantId}/products`) : Promise.resolve([] as Product[])),
    [tenantId],
  );
  const productName = (id: number) => products.data?.find((p) => p.id === id)?.name ?? `product ${id}`;
  const grant = async (e: FormEvent) => {
    e.preventDefault();
    const body = { role_id: Number(roleId), ...(productId ? { product_id: Number(productId) } : {}) };
    if (await action.run(() => api(path, { method: "POST", body }))) {
      setRoleId("");
      setProductId("");
      grants.reload();
    }
  };
  const revoke = async (a: Assignment) => {
    if (await action.run(() => api(`${path}/${a.id}`, { method: "DELETE" }))) grants.reload();
  };
  return (
    <div className="grants">
      <h3>Roles of {user.username}</h3>
      <ErrorBox error={grants.error || action.error} />
      <ul>
        {(grants.data ?? []).map((a) => (
          <li key={a.id}>
            {a.role_name}
            {a.product_id !== null && <span className="muted"> (only {productName(a.product_id)})</span>}
            {canAssign && (
              <button className="link" disabled={action.busy} onClick={() => void revoke(a)}>Revoke</button>
            )}
          </li>
        ))}
        {grants.data && grants.data.length === 0 && <li className="muted">No roles.</li>}
      </ul>
      {canAssign && (
        <form className="row" onSubmit={grant}>
          <label className="field">
            <span>Grant role</span>
            <select value={roleId} onChange={(e) => setRoleId(e.target.value)} required>
              <option value="">Choose a role</option>
              {roles.filter((r) => r.name !== "SuperAdmin").map((r) => (
                <option key={r.id} value={r.id}>{r.name}</option>
              ))}
            </select>
          </label>
          {(products.data ?? []).length > 0 && (
            <label className="field">
              <span>Scope</span>
              <select value={productId} onChange={(e) => setProductId(e.target.value)}>
                <option value="">Whole tenant</option>
                {(products.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>Only product {p.name}</option>
                ))}
              </select>
            </label>
          )}
          <button type="submit" disabled={action.busy || !roleId}>Grant</button>
        </form>
      )}
    </div>
  );
}

function CreateUser({ tenantId, roles, onCreated }: { tenantId: number; roles: Role[]; onCreated: (name: string) => void }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const [roleIds, setRoleIds] = useState<number[]>([]);
  const action = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { username, password, must_change_password: mustChange, role_ids: roleIds, ...(email ? { email } : {}) };
    if (await action.run(() => api(`/tenants/${tenantId}/users`, { method: "POST", body }))) {
      onCreated(username);
      setUsername("");
      setEmail("");
      setPassword("");
      setRoleIds([]);
    }
  };
  return (
    <Card title="Create user">
      <form onSubmit={submit}>
        <div className="row">
          <Field label="Username" value={username} onChange={setUsername} autoComplete="off" required />
          <Field label="Email (optional)" type="email" value={email} onChange={setEmail} autoComplete="off" />
          <Field label="Initial password" type="password" value={password} onChange={setPassword} autoComplete="new-password" required />
        </div>
        <p className="hint">{PASSWORD_HINT}</p>
        <label className="check">
          <input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} />
          Must change password at first sign-in
        </label>
        {roles.length > 0 && (
          <fieldset className="checks">
            <legend>Roles</legend>
            {roles.filter((r) => r.name !== "SuperAdmin").map((r) => (
              <label key={r.id} className="check">
                <input
                  type="checkbox"
                  checked={roleIds.includes(r.id)}
                  onChange={(e) => setRoleIds(e.target.checked ? [...roleIds, r.id] : roleIds.filter((x) => x !== r.id))}
                />
                {r.name}
              </label>
            ))}
          </fieldset>
        )}
        <ErrorBox error={action.error} />
        <button type="submit" className="primary" disabled={action.busy}>Create user</button>
      </form>
    </Card>
  );
}
