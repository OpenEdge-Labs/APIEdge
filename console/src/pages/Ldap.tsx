// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// LDAP and Active Directory directories of a tenant (T-023), used by the basic-ldap policy. The
// service account's password is write-only.
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can } from "../access";
import {
  createBody,
  directoryProblems,
  emptyDirectoryForm,
  formFromDirectory,
  updateBody,
  type Directory,
  type DirectoryForm,
  type LdapSecurity,
} from "../ldap";
import type { Me } from "../types";
import { Card, ErrorBox, Field, Notice, useAction, useLoad } from "../ui";

interface TruststoreRef {
  id: number;
  name: string;
}

const SECURITY: { value: LdapSecurity; label: string; port: string }[] = [
  { value: "ldaps", label: "LDAPS (TLS from the start)", port: "636" },
  { value: "starttls", label: "StartTLS", port: "389" },
  { value: "plain", label: "Plain LDAP (no encryption: isolated lab networks only)", port: "389" },
];

export function LdapPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/ldap/directories`;
  const directories = useLoad(() => api<Directory[]>(base), [base]);
  const stores = useLoad(
    () => (can(me, "tls:read") ? api<TruststoreRef[]>(`/tenants/${tenantId}/tls/truststores`) : Promise.resolve(null)),
    [tenantId],
  );
  const action = useAction();
  const manage = can(me, "ldap:manage");
  const [form, setForm] = useState<DirectoryForm>(emptyDirectoryForm);
  const [editing, setEditing] = useState<Directory | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const problems = directoryProblems(form, editing);

  const set = (patch: Partial<DirectoryForm>) => setForm((f) => ({ ...f, ...patch }));
  const reset = () => {
    setForm(emptyDirectoryForm);
    setEditing(null);
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    const done = await action.run(() =>
      editing
        ? api(`${base}/${editing.id}`, { method: "PATCH", body: updateBody(form) })
        : api(base, { method: "POST", body: createBody(form) }),
    );
    if (done) {
      setNotice(editing ? `Directory "${editing.name}" saved.` : `Directory "${form.name.trim()}" created.`);
      reset();
      directories.reload();
    }
  };
  const test = async (d: Directory) => {
    setNotice(null);
    await action.run(async () => {
      const out = await api<{ ok: boolean; message: string }>(`${base}/${d.id}/test`, { method: "POST" });
      setNotice(out.ok ? `"${d.name}": connected.` : `"${d.name}" failed: ${out.message}`);
    });
  };
  const remove = async (d: Directory) => {
    if (!window.confirm(`Delete the directory "${d.name}"?`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${d.id}`, { method: "DELETE" }))) {
      if (editing?.id === d.id) reset();
      directories.reload();
    }
  };

  return (
    <>
      <ErrorBox error={directories.error || stores.error || action.error} />
      <Notice text={notice} />
      <Card title="Directories">
        <p className="hint">
          A <em>Basic authentication (LDAP)</em> policy on an API checks user names and passwords against one of these directories.
        </p>
        <table>
          <thead>
            <tr><th>Id</th><th>Name</th><th>Server</th><th>Security</th><th>Service account</th><th>Used by</th><th /></tr>
          </thead>
          <tbody>
            {(directories.data ?? []).map((d) => (
              <tr key={d.id}>
                <td>{d.id}</td>
                <td>{d.name}</td>
                <td><code>{d.host}:{d.port}</code></td>
                <td><span className={`lifecycle ${d.security === "plain" ? "deprecated" : "published"}`}>{d.security}</span></td>
                <td>{d.bind_dn ? <code>{d.bind_dn}</code> : <span className="muted">none</span>}</td>
                <td>{d.apis.join(", ") || <span className="muted">-</span>}</td>
                <td className="actions">
                  {manage && (
                    <>
                      <button disabled={action.busy} onClick={() => void test(d)}>Test</button>
                      <button disabled={action.busy} onClick={() => { setEditing(d); setForm(formFromDirectory(d)); setNotice(null); }}>Edit</button>
                      <button className="danger" disabled={action.busy} onClick={() => void remove(d)}>Delete</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {directories.data && directories.data.length === 0 && (
              <tr><td colSpan={7} className="muted">No directories yet.</td></tr>
            )}
          </tbody>
        </table>
      </Card>
      {manage && (
        <Card title={editing ? `Edit ${editing.name}` : "Add a directory"}>
          <form onSubmit={submit}>
            <div className="row">
              {!editing && <Field label="Name" value={form.name} onChange={(v) => set({ name: v })} placeholder="corp-ad" required />}
              <Field label="Host" value={form.host} onChange={(v) => set({ host: v })} placeholder="ldap.example.com" required />
              <label className="field">
                <span>Security</span>
                <select
                  value={form.security}
                  onChange={(e) => {
                    const choice = SECURITY.find((s) => s.value === e.target.value) ?? SECURITY[0];
                    set({ security: choice.value, port: choice.port });
                  }}
                >
                  {SECURITY.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                </select>
              </label>
              <Field label="Port" type="number" value={form.port} onChange={(v) => set({ port: v })} required />
            </div>
            <div className="row">
              <label className="field">
                <span>CAs that verify the server</span>
                <select value={form.truststore_id} onChange={(e) => set({ truststore_id: e.target.value })}>
                  <option value="">System certificate store</option>
                  {(stores.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </label>
              <Field label="Timeout (s)" type="number" value={form.timeout_seconds} onChange={(v) => set({ timeout_seconds: v })} />
            </div>
            <div className="row">
              <Field label="Service account bind DN (optional)" value={form.bind_dn} onChange={(v) => set({ bind_dn: v })} placeholder="cn=gateway,ou=services,dc=example,dc=com" />
              <Field
                label={editing?.bind_password_set ? "Service account password (empty keeps the stored one)" : "Service account password"}
                type="password"
                autoComplete="new-password"
                value={form.bind_password}
                onChange={(v) => set({ bind_password: v })}
              />
            </div>
            <div className="row">
              <Field label="User base DN" value={form.user_base_dn} onChange={(v) => set({ user_base_dn: v })} placeholder="ou=people,dc=example,dc=com" />
              <Field label="User filter" value={form.user_filter} onChange={(v) => set({ user_filter: v })} placeholder="(sAMAccountName={username})" />
            </div>
            <div className="row">
              <Field label="User DN template, instead of searching (optional)" value={form.user_dn_template} onChange={(v) => set({ user_dn_template: v })} placeholder="uid={username},ou=people,dc=example,dc=com" />
            </div>
            <div className="row">
              <Field label="User name attribute" value={form.username_attribute} onChange={(v) => set({ username_attribute: v })} />
              <Field label="Email attribute" value={form.email_attribute} onChange={(v) => set({ email_attribute: v })} />
              <Field label="Display name attribute" value={form.name_attribute} onChange={(v) => set({ name_attribute: v })} />
            </div>
            {problems.map((p) => <p key={p} className="muted">{p}</p>)}
            <button type="submit" className="primary" disabled={action.busy || !form.host.trim() || (!editing && !form.name.trim()) || problems.length > 0}>
              {editing ? "Save" : "Add directory"}
            </button>{" "}
            {editing && <button type="button" onClick={reset}>Cancel</button>}
          </form>
        </Card>
      )}
    </>
  );
}
