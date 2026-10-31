// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";

type Health = "checking" | "ok" | "unavailable";

/** T-001 shell: shows the gateway health. Login and the admin panel arrive with T-004. */
export function App() {
  const [health, setHealth] = useState<Health>("checking");

  useEffect(() => {
    let cancelled = false;
    fetch("/readyz", { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((body: { status?: string }) => {
        if (!cancelled) setHealth(body.status === "ok" ? "ok" : "unavailable");
      })
      .catch(() => {
        if (!cancelled) setHealth("unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="shell">
      <header>
        <h1>APIEdge</h1>
        <p className="tagline">API Gateway console</p>
      </header>
      <section className="card">
        <h2>Gateway status</h2>
        <p data-testid="health" className={`status status-${health}`}>
          {health === "checking" ? "Checking..." : health === "ok" ? "Running" : "Unavailable"}
        </p>
        <p className="muted">
          Sign-in and the admin panel will be available in an upcoming release.
        </p>
      </section>
    </main>
  );
}
