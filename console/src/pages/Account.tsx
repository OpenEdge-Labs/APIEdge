// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { ChangePassword } from "../auth";
import type { Me, MfaSetup } from "../types";
import { Card, ErrorBox, Field, Notice, useAction } from "../ui";

export function AccountPage({ me, onChanged }: { me: Me; onChanged: () => void }) {
  const [notice, setNotice] = useState<string | null>(null);
  return (
    <>
      <Card title="My account">
        <dl className="props">
          <dt>Username</dt>
          <dd>{me.username}</dd>
          <dt>Email</dt>
          <dd>{me.email ?? "-"}</dd>
          <dt>Scope</dt>
          <dd>{me.is_superadmin ? "SuperAdmin (platform)" : `Tenant ${me.tenant_id}`}</dd>
        </dl>
      </Card>
      <Card title="Change password">
        <Notice text={notice} />
        <ChangePassword
          forced={false}
          onDone={() => {
            setNotice("Password changed. Your other sessions have ended.");
            onChanged();
          }}
        />
      </Card>
      <Mfa me={me} onChanged={onChanged} />
    </>
  );
}

function Mfa({ me, onChanged }: { me: Me; onChanged: () => void }) {
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const action = useAction();
  const [notice, setNotice] = useState<string | null>(null);

  const start = () =>
    action.run(async () => {
      setNotice(null);
      setSetup(await api<MfaSetup>("/auth/mfa/setup", { method: "POST" }));
    });
  const enable = async (e: FormEvent) => {
    e.preventDefault();
    if (await action.run(() => api("/auth/mfa/enable", { method: "POST", body: { code: code.trim() } }))) {
      setSetup(null);
      setCode("");
      setNotice("Two-factor authentication is on.");
      onChanged();
    }
  };
  const disable = async (e: FormEvent) => {
    e.preventDefault();
    if (await action.run(() => api("/auth/mfa/disable", { method: "POST", body: { password, code: code.trim() } }))) {
      setPassword("");
      setCode("");
      setNotice("Two-factor authentication is off.");
      onChanged();
    }
  };

  return (
    <Card title="Two-factor authentication (TOTP)">
      <Notice text={notice} />
      <ErrorBox error={action.error} />
      {me.mfa_enabled ? (
        <form onSubmit={disable}>
          <p>Two-factor authentication is <strong>on</strong>. To turn it off, confirm with your password and a current code.</p>
          <div className="row">
            <Field label="Password" type="password" value={password} onChange={setPassword} autoComplete="current-password" required />
            <Field label="Authenticator code" value={code} onChange={setCode} inputMode="numeric" autoComplete="one-time-code" required />
          </div>
          <button type="submit" className="danger" disabled={action.busy}>Turn off</button>
        </form>
      ) : setup ? (
        <form onSubmit={enable}>
          <p>Add this account to your authenticator app, then enter the 6-digit code it shows.</p>
          <dl className="props">
            <dt>Secret key</dt>
            <dd><code className="secret">{setup.secret}</code></dd>
            <dt>Setup URI</dt>
            <dd><code className="secret">{setup.otpauth_uri}</code></dd>
          </dl>
          <Field label="Authenticator code" value={code} onChange={setCode} inputMode="numeric" autoComplete="one-time-code" required />
          <div className="row">
            <button type="submit" className="primary" disabled={action.busy}>Turn on</button>
            <button type="button" onClick={() => setSetup(null)}>Cancel</button>
          </div>
        </form>
      ) : (
        <>
          <p>Two-factor authentication is <strong>off</strong>. Turn it on to require a code from an authenticator app at sign-in.</p>
          <button className="primary" disabled={action.busy} onClick={() => void start()}>Set up</button>
        </>
      )}
    </Card>
  );
}
