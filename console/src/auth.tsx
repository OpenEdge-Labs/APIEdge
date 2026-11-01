// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// Sign-in (password, then TOTP when the account has MFA) and the forced password change.
import { useState, type FormEvent } from "react";
import { ApiError, api } from "./api";
import { ErrorBox, Field, useAction } from "./ui";

export const PASSWORD_HINT =
  "12-128 characters, no leading or trailing space, must not contain your username or be a common password. Passphrases are welcome.";

export function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needMfa, setNeedMfa] = useState(false);
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    let mfaStep = false;
    const ok = await run(async () => {
      const body: Record<string, string> = { username, password };
      if (needMfa) body.totp_code = code.trim();
      try {
        await api("/auth/login", { method: "POST", body, noRefresh: true });
      } catch (err) {
        // Password accepted, the account has MFA: ask for the code without showing an error.
        if (err instanceof ApiError && err.code === "mfa_required" && !needMfa) {
          mfaStep = true;
          return;
        }
        throw err;
      }
    });
    if (mfaStep) {
      setNeedMfa(true);
    } else if (ok) {
      setPassword("");
      onSignedIn();
    }
  };

  return (
    <main className="login">
      <form className="card login-card" onSubmit={submit} aria-label="Sign in">
        <h1>APIEdge</h1>
        <p className="muted">Sign in to the console</p>
        <Field label="Username" value={username} onChange={setUsername} autoComplete="username" required autoFocus />
        <Field
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          required
        />
        {needMfa && (
          <Field
            label="Authenticator code"
            value={code}
            onChange={setCode}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            required
            autoFocus
          />
        )}
        <ErrorBox error={error} />
        <button type="submit" className="primary" disabled={busy}>
          {busy ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </main>
  );
}

/** Change own password. `forced` is the first-sign-in variant shown before anything else. */
export function ChangePassword({ forced, onDone }: { forced: boolean; onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const { busy, error, run, setError } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== repeat) {
      setError(new Error("The new passwords do not match."));
      return;
    }
    const ok = await run(async () => {
      await api("/auth/change-password", {
        method: "POST",
        body: { current_password: current, new_password: next },
      });
    });
    if (ok) {
      setCurrent("");
      setNext("");
      setRepeat("");
      onDone();
    }
  };

  return (
    <form className={forced ? "card login-card" : ""} onSubmit={submit} aria-label="Change password">
      {forced && (
        <>
          <h1>Change your password</h1>
          <p className="muted">This is your first sign-in (or your password was reset). Choose a new password to continue.</p>
        </>
      )}
      <Field label="Current password" type="password" value={current} onChange={setCurrent} autoComplete="current-password" required />
      <Field label="New password" type="password" value={next} onChange={setNext} autoComplete="new-password" required />
      <Field label="Repeat new password" type="password" value={repeat} onChange={setRepeat} autoComplete="new-password" required />
      <p className="hint">{PASSWORD_HINT}</p>
      <ErrorBox error={error} />
      <button type="submit" className="primary" disabled={busy}>
        {busy ? "Saving..." : "Change password"}
      </button>
    </form>
  );
}
