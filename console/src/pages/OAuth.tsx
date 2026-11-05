// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// The tenant's OAuth 2.0 / OpenID Connect server (T-023): endpoints, clients (the secret is shown
// once) and token signing keys (rotation keeps the previous key published until it is deleted).
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can } from "../access";
import { clientBody, clientProblems, type ClientForm, type GrantType } from "../oauth";
import type { Me } from "../types";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

interface Server {
  issuer: string;
  discovery_url: string;
  token_endpoint: string;
  authorization_endpoint: string;
  jwks_uri: string;
  active_key_id: string | null;
  user_registry: string;
}

interface Client {
  id: number;
  client_id: string;
  name: string;
  description: string;
  client_type: "confidential" | "public";
  secret_prefix: string | null;
  grant_types: GrantType[];
  redirect_uris: string[];
  scopes: string[];
  audiences: string[];
  access_token_ttl: number;
  refresh_token_ttl: number;
  enabled: boolean;
}

interface SigningKey {
  id: number;
  kid: string;
  algorithm: string;
  status: "active" | "retired";
  created_at: string;
  retired_at: string | null;
}

const GRANTS: { value: GrantType; label: string }[] = [
  { value: "client_credentials", label: "Client credentials" },
  { value: "authorization_code", label: "Authorization code (PKCE)" },
  { value: "refresh_token", label: "Refresh token" },
];

const emptyForm: ClientForm = {
  name: "",
  description: "",
  client_type: "confidential",
  grant_types: ["client_credentials"],
  redirect_uris: "",
  scopes: "",
  audiences: "",
  access_token_ttl: "600",
  refresh_token_ttl: "86400",
};

export function OAuthPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/oauth`;
  const server = useLoad(() => api<Server>(`${base}/server`), [base]);
  const clients = useLoad(() => api<Client[]>(`${base}/clients`), [base]);
  const keys = useLoad(() => api<SigningKey[]>(`${base}/keys`), [base]);
  const action = useAction();
  const manage = can(me, "oauth:manage");
  const [form, setForm] = useState<ClientForm>(emptyForm);
  const [notice, setNotice] = useState<string | null>(null);
  const [secret, setSecret] = useState<{ name: string; clientId: string; secret: string } | null>(null);
  const problems = clientProblems(form);

  const toggleGrant = (g: GrantType) =>
    setForm((f) => ({
      ...f,
      grant_types: f.grant_types.includes(g) ? f.grant_types.filter((x) => x !== g) : [...f.grant_types, g],
    }));
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    setSecret(null);
    await action.run(async () => {
      const out = await api<Client & { client_secret: string | null }>(`${base}/clients`, { method: "POST", body: clientBody(form) });
      if (out.client_secret) setSecret({ name: out.name, clientId: out.client_id, secret: out.client_secret });
      else setNotice(`Public client "${out.name}" registered (client id ${out.client_id}).`);
      setForm(emptyForm);
      clients.reload();
      keys.reload();
      server.reload();
    });
  };
  const rotateSecret = async (c: Client) => {
    if (!window.confirm(`Issue a new secret for "${c.name}"? The current secret stops working at once.`)) return;
    setNotice(null);
    await action.run(async () => {
      const out = await api<{ client_id: string; client_secret: string }>(`${base}/clients/${c.id}/secret`, { method: "POST" });
      setSecret({ name: c.name, clientId: out.client_id, secret: out.client_secret });
      clients.reload();
    });
  };
  const toggle = async (c: Client) => {
    setNotice(null);
    if (await action.run(() => api(`${base}/clients/${c.id}`, { method: "PATCH", body: { enabled: !c.enabled } }))) clients.reload();
  };
  const removeClient = async (c: Client) => {
    if (!window.confirm(`Delete the client "${c.name}"? Its refresh tokens stop working.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/clients/${c.id}`, { method: "DELETE" }))) {
      setNotice(`Client "${c.name}" deleted.`);
      clients.reload();
    }
  };
  const rotateKey = async () => {
    if (!window.confirm("Create a new signing key? Tokens signed with the current key stay valid until they expire.")) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/keys`, { method: "POST" }))) {
      setNotice("New signing key active. Delete the retired key once its tokens have expired.");
      keys.reload();
      server.reload();
    }
  };
  const removeKey = async (k: SigningKey) => {
    if (!window.confirm(`Delete the retired key ${k.kid}? Tokens it signed stop validating.`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/keys/${k.id}`, { method: "DELETE" }))) keys.reload();
  };

  return (
    <>
      <ErrorBox error={server.error || clients.error || keys.error || action.error} />
      <Notice text={notice} />
      {secret && (
        <div className="notice" role="status">
          <p>
            Client secret for <strong>{secret.name}</strong> (client id <code>{secret.clientId}</code>). Copy it now; it will not be
            shown again.
          </p>
          <code className="secret-once">{secret.secret}</code>{" "}
          <button type="button" onClick={() => void navigator.clipboard?.writeText(secret.secret)}>Copy</button>{" "}
          <button type="button" onClick={() => setSecret(null)}>Done</button>
        </div>
      )}
      <Card title="Authorization server">
        {server.data && (
          <dl className="props">
            <dt>Issuer</dt>
            <dd><code>{server.data.issuer}</code></dd>
            <dt>Discovery</dt>
            <dd><code>{server.data.discovery_url}</code></dd>
            <dt>Token endpoint</dt>
            <dd><code>{server.data.token_endpoint}</code></dd>
            <dt>Sign-in</dt>
            <dd>This tenant's console users ({server.data.user_registry} user registry)</dd>
          </dl>
        )}
        <p className="hint">
          APIs validate these tokens with a JWT policy that has <em>Built-in issuer</em> switched on.
        </p>
      </Card>
      <Card title="Clients">
        <table>
          <thead>
            <tr><th>Name</th><th>Client id</th><th>Type</th><th>Grants</th><th>Scopes</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {(clients.data ?? []).map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td><code>{c.client_id}</code></td>
                <td>{c.client_type}{c.secret_prefix ? <span className="muted"> ({c.secret_prefix}...)</span> : null}</td>
                <td>{c.grant_types.join(", ")}</td>
                <td>{c.scopes.join(" ") || "-"}</td>
                <td><span className={`lifecycle ${c.enabled ? "published" : "retired"}`}>{c.enabled ? "enabled" : "disabled"}</span></td>
                <td className="actions">
                  {manage && (
                    <>
                      {c.client_type === "confidential" && (
                        <button disabled={action.busy} onClick={() => void rotateSecret(c)}>New secret</button>
                      )}
                      <button disabled={action.busy} onClick={() => void toggle(c)}>{c.enabled ? "Disable" : "Enable"}</button>
                      <button className="danger" disabled={action.busy} onClick={() => void removeClient(c)}>Delete</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {clients.data && clients.data.length === 0 && (
              <tr><td colSpan={7} className="muted">No clients yet.</td></tr>
            )}
          </tbody>
        </table>
        {manage && (
          <form onSubmit={create}>
            <div className="row">
              <Field label="Name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} placeholder="billing service" required />
              <label className="field">
                <span>Type</span>
                <select value={form.client_type} onChange={(e) => setForm({ ...form, client_type: e.target.value as ClientForm["client_type"] })}>
                  <option value="confidential">Confidential (has a secret)</option>
                  <option value="public">Public (browser or native app, PKCE only)</option>
                </select>
              </label>
            </div>
            <fieldset className="checks">
              <legend>Grant types</legend>
              {GRANTS.map((g) => (
                <label key={g.value} className="check">
                  <input type="checkbox" checked={form.grant_types.includes(g.value)} onChange={() => toggleGrant(g.value)} /> {g.label}
                </label>
              ))}
            </fieldset>
            <div className="row">
              <Field label="Redirect URIs (space separated)" value={form.redirect_uris} onChange={(v) => setForm({ ...form, redirect_uris: v })} placeholder="https://app.example.com/callback" />
              <Field label="Allowed scopes" value={form.scopes} onChange={(v) => setForm({ ...form, scopes: v })} placeholder="openid profile orders.read" />
              <Field label="Audiences" value={form.audiences} onChange={(v) => setForm({ ...form, audiences: v })} placeholder="orders-api" />
            </div>
            <div className="row">
              <Field label="Access token lifetime (s)" type="number" value={form.access_token_ttl} onChange={(v) => setForm({ ...form, access_token_ttl: v })} />
              <Field label="Refresh token lifetime (s)" type="number" value={form.refresh_token_ttl} onChange={(v) => setForm({ ...form, refresh_token_ttl: v })} />
            </div>
            {problems.map((p) => <p key={p} className="muted">{p}</p>)}
            <button type="submit" className="primary" disabled={action.busy || !form.name.trim() || problems.length > 0}>Register client</button>
          </form>
        )}
      </Card>
      <Card title="Signing keys" actions={manage ? <button disabled={action.busy} onClick={() => void rotateKey()}>Rotate key</button> : undefined}>
        <p className="hint">Private keys are stored encrypted and never shown. Retired keys stay in the JWKS until deleted.</p>
        <table>
          <thead>
            <tr><th>Key id</th><th>Algorithm</th><th>Status</th><th>Created</th><th>Retired</th><th /></tr>
          </thead>
          <tbody>
            {(keys.data ?? []).map((k) => (
              <tr key={k.id}>
                <td><code>{k.kid}</code></td>
                <td>{k.algorithm}</td>
                <td><span className={`lifecycle ${k.status === "active" ? "published" : "deprecated"}`}>{k.status}</span></td>
                <td>{fmtDate(k.created_at)}</td>
                <td>{fmtDate(k.retired_at)}</td>
                <td className="actions">
                  {manage && k.status === "retired" && (
                    <button className="danger" disabled={action.busy} onClick={() => void removeKey(k)}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
            {keys.data && keys.data.length === 0 && (
              <tr><td colSpan={6} className="muted">No key yet: one is created with the first client.</td></tr>
            )}
          </tbody>
        </table>
      </Card>
    </>
  );
}
