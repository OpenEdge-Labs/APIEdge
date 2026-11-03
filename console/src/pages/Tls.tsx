// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// TLS material of a tenant (T-023): truststores (CA bundles used by the mtls policy) and
// keystores (certificate chain plus private key; the key is write-only).
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can } from "../access";
import type { Me } from "../types";
import { profileBody, statusClass } from "../tls";
import { Card, ErrorBox, Field, Notice, fmtDate, useAction, useLoad } from "../ui";

export interface CertInfo {
  subject: string;
  issuer: string;
  common_name: string;
  serial: string;
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
  key_type: string;
  is_ca: boolean;
  dns_names: string[];
  status: "valid" | "expiring" | "expired" | "not_yet_valid";
}

interface Truststore {
  id: number;
  name: string;
  description: string;
  certificates: CertInfo[];
}

interface Keystore {
  id: number;
  name: string;
  description: string;
  key_type: string;
  certificate: CertInfo;
  chain: CertInfo[];
}

interface TlsProfile {
  id: number;
  name: string;
  description: string;
  min_version: "1.2" | "1.3";
  ciphers: string | null;
  truststore_id: number | null;
  keystore_id: number | null;
  apis: string[];
}

function Cert({ c }: { c: CertInfo }) {
  return (
    <div className="cert">
      <strong>{c.subject}</strong> <span className={`lifecycle ${statusClass(c.status)}`}>{c.status.replace(/_/g, " ")}</span>
      <div className="muted">
        issuer {c.issuer} - {c.key_type}
        {c.is_ca ? " - CA" : ""} - expires {fmtDate(c.not_after)}
      </div>
      <div className="muted"><code>SHA-256 {c.fingerprint_sha256}</code></div>
    </div>
  );
}

function TextArea({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      <textarea rows={6} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} spellCheck={false} />
    </label>
  );
}

export function TlsPage({ me, tenantId }: { me: Me; tenantId: number }) {
  const base = `/tenants/${tenantId}/tls`;
  const stores = useLoad(() => api<Truststore[]>(`${base}/truststores`), [base]);
  const keys = useLoad(() => api<Keystore[]>(`${base}/keystores`), [base]);
  const profiles = useLoad(() => api<TlsProfile[]>(`${base}/profiles`), [base]);
  const emptyProfile = { name: "", description: "", min_version: "1.2", ciphers: "", truststore_id: "", keystore_id: "" };
  const [pf, setPf] = useState(emptyProfile);
  const action = useAction();
  const manage = can(me, "tls:manage");
  const [notice, setNotice] = useState<string | null>(null);
  const [ts, setTs] = useState({ name: "", description: "", certificates: "" });
  const [ks, setKs] = useState({ name: "", description: "", certificate_chain: "", private_key: "", passphrase: "" });

  const createStore = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    if (await action.run(() => api(`${base}/truststores`, { method: "POST", body: ts }))) {
      setTs({ name: "", description: "", certificates: "" });
      setNotice("Truststore created.");
      stores.reload();
    }
  };
  const createKey = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    const body: Record<string, unknown> = { ...ks, passphrase: ks.passphrase || null };
    if (await action.run(() => api(`${base}/keystores`, { method: "POST", body }))) {
      setKs({ name: "", description: "", certificate_chain: "", private_key: "", passphrase: "" });
      setNotice("Keystore created. The private key is stored encrypted and is never shown again.");
      keys.reload();
    }
  };
  const createProfile = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    if (await action.run(() => api(`${base}/profiles`, { method: "POST", body: profileBody(pf) }))) {
      setPf(emptyProfile);
      setNotice("TLS profile created. Choose it for an API under Products > APIs.");
      profiles.reload();
    }
  };
  const storeName = (id: number | null) => (id === null ? "-" : (stores.data ?? []).find((t) => t.id === id)?.name ?? `#${id}`);
  const keyName = (id: number | null) => (id === null ? "-" : (keys.data ?? []).find((k) => k.id === id)?.name ?? `#${id}`);
  const remove = async (kind: "truststores" | "keystores" | "profiles", id: number, name: string) => {
    if (!window.confirm(`Delete "${name}"?`)) return;
    setNotice(null);
    if (await action.run(() => api(`${base}/${kind}/${id}`, { method: "DELETE" }))) {
      setNotice(`"${name}" deleted.`);
      if (kind === "truststores") stores.reload();
      else if (kind === "keystores") keys.reload();
      else profiles.reload();
    }
  };

  return (
    <>
      <ErrorBox error={stores.error || keys.error || profiles.error || action.error} />
      <Notice text={notice} />
      <Card title="Truststores">
        <p className="hint">
          CA certificates trusted for client certificates. An API's <em>Client certificate (mTLS)</em> policy names a
          truststore by its id.
        </p>
        <table>
          <thead>
            <tr><th>Id</th><th>Name</th><th>Certificates</th><th /></tr>
          </thead>
          <tbody>
            {(stores.data ?? []).map((t) => (
              <tr key={t.id}>
                <td>{t.id}</td>
                <td>{t.name}<div className="muted">{t.description}</div></td>
                <td>{t.certificates.map((c) => <Cert key={c.fingerprint_sha256} c={c} />)}</td>
                <td className="actions">
                  {manage && <button className="danger" disabled={action.busy} onClick={() => void remove("truststores", t.id, t.name)}>Delete</button>}
                </td>
              </tr>
            ))}
            {stores.data && stores.data.length === 0 && (
              <tr><td colSpan={4} className="muted">No truststores yet.</td></tr>
            )}
          </tbody>
        </table>
        {manage && (
          <form onSubmit={createStore}>
            <div className="row">
              <Field label="Name" value={ts.name} onChange={(v) => setTs({ ...ts, name: v })} required />
              <Field label="Description" value={ts.description} onChange={(v) => setTs({ ...ts, description: v })} />
            </div>
            <TextArea label="CA certificates (PEM)" value={ts.certificates} onChange={(v) => setTs({ ...ts, certificates: v })} placeholder="-----BEGIN CERTIFICATE-----" />
            <button type="submit" className="primary" disabled={action.busy || !ts.name.trim() || !ts.certificates.trim()}>Create truststore</button>
          </form>
        )}
      </Card>
      <Card title="Keystores">
        <p className="hint">A certificate chain with its private key. The key is encrypted at rest and never returned.</p>
        <table>
          <thead>
            <tr><th>Id</th><th>Name</th><th>Certificate</th><th /></tr>
          </thead>
          <tbody>
            {(keys.data ?? []).map((k) => (
              <tr key={k.id}>
                <td>{k.id}</td>
                <td>{k.name}<div className="muted">{k.description}</div></td>
                <td>
                  <Cert c={k.certificate} />
                  {k.chain.length > 0 && <div className="muted">+ {k.chain.length} chain certificate(s)</div>}
                </td>
                <td className="actions">
                  {manage && <button className="danger" disabled={action.busy} onClick={() => void remove("keystores", k.id, k.name)}>Delete</button>}
                </td>
              </tr>
            ))}
            {keys.data && keys.data.length === 0 && (
              <tr><td colSpan={4} className="muted">No keystores yet.</td></tr>
            )}
          </tbody>
        </table>
        {manage && (
          <form onSubmit={createKey}>
            <div className="row">
              <Field label="Name" value={ks.name} onChange={(v) => setKs({ ...ks, name: v })} required />
              <Field label="Description" value={ks.description} onChange={(v) => setKs({ ...ks, description: v })} />
            </div>
            <TextArea label="Certificate chain (PEM, leaf first)" value={ks.certificate_chain} onChange={(v) => setKs({ ...ks, certificate_chain: v })} placeholder="-----BEGIN CERTIFICATE-----" />
            <TextArea label="Private key (PEM)" value={ks.private_key} onChange={(v) => setKs({ ...ks, private_key: v })} placeholder="-----BEGIN PRIVATE KEY-----" />
            <Field label="Key passphrase (if encrypted)" type="password" autoComplete="off" value={ks.passphrase} onChange={(v) => setKs({ ...ks, passphrase: v })} />
            <button type="submit" className="primary" disabled={action.busy || !ks.name.trim() || !ks.certificate_chain.trim() || !ks.private_key.trim()}>Create keystore</button>
          </form>
        )}
      </Card>
      <Card title="Upstream TLS profiles">
        <p className="hint">
          How the gateway connects to an API's HTTPS upstreams: lowest TLS version, the truststore that verifies the upstream
          (default: the gateway's CA bundle) and an optional keystore sent as client certificate (upstream mTLS). Certificates
          and host names are always verified.
        </p>
        <table>
          <thead>
            <tr><th>Name</th><th>TLS</th><th>Truststore</th><th>Client certificate</th><th>Used by</th><th /></tr>
          </thead>
          <tbody>
            {(profiles.data ?? []).map((p) => (
              <tr key={p.id}>
                <td>{p.name}<div className="muted">{p.description}</div></td>
                <td>{p.min_version}+{p.ciphers ? <div className="muted"><code>{p.ciphers}</code></div> : null}</td>
                <td>{storeName(p.truststore_id)}</td>
                <td>{keyName(p.keystore_id)}</td>
                <td>{p.apis.length ? p.apis.join(", ") : <span className="muted">no APIs</span>}</td>
                <td className="actions">
                  {manage && <button className="danger" disabled={action.busy} onClick={() => void remove("profiles", p.id, p.name)}>Delete</button>}
                </td>
              </tr>
            ))}
            {profiles.data && profiles.data.length === 0 && (
              <tr><td colSpan={6} className="muted">No TLS profiles yet.</td></tr>
            )}
          </tbody>
        </table>
        {manage && (
          <form onSubmit={createProfile}>
            <div className="row">
              <Field label="Name" value={pf.name} onChange={(v) => setPf({ ...pf, name: v })} required />
              <label className="field">
                <span>Lowest TLS version</span>
                <select value={pf.min_version} onChange={(e) => setPf({ ...pf, min_version: e.target.value })}>
                  <option value="1.2">TLS 1.2</option>
                  <option value="1.3">TLS 1.3</option>
                </select>
              </label>
              <label className="field">
                <span>Truststore</span>
                <select value={pf.truststore_id} onChange={(e) => setPf({ ...pf, truststore_id: e.target.value })}>
                  <option value="">Gateway CA bundle</option>
                  {(stores.data ?? []).map((t) => <option key={t.id} value={String(t.id)}>{t.name}</option>)}
                </select>
              </label>
              <label className="field">
                <span>Client certificate</span>
                <select value={pf.keystore_id} onChange={(e) => setPf({ ...pf, keystore_id: e.target.value })}>
                  <option value="">None</option>
                  {(keys.data ?? []).map((k) => <option key={k.id} value={String(k.id)}>{k.name}</option>)}
                </select>
              </label>
            </div>
            <div className="row">
              <Field label="Description" value={pf.description} onChange={(v) => setPf({ ...pf, description: v })} />
              <Field label="TLS 1.2 ciphers (OpenSSL syntax, optional)" value={pf.ciphers} onChange={(v) => setPf({ ...pf, ciphers: v })} placeholder="ECDHE+AESGCM" />
            </div>
            <button type="submit" className="primary" disabled={action.busy || !pf.name.trim()}>Create TLS profile</button>
          </form>
        )}
      </Card>
    </>
  );
}
