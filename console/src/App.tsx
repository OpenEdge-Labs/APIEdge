// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// Console shell: session state, the forced password change, permission-aware navigation and the
// tenant switcher. Pages are addressed by the location hash (#/users), so the server only ever
// serves index.html at "/".
import { useCallback, useEffect, useState } from "react";
import { ApiError, api, setSessionEndedHandler } from "./api";
import { navFor, pageFromHash, type Page } from "./access";
import { ChangePassword, Login } from "./auth";
import type { Me, Tenant } from "./types";
import { AccountPage } from "./pages/Account";
import { AnalyticsPage } from "./pages/Analytics";
import { AuditPage } from "./pages/Audit";
import { ProductsPage } from "./pages/Products";
import { RolesPage } from "./pages/Roles";
import { SettingsPage } from "./pages/Settings";
import { TenantsPage } from "./pages/Tenants";
import { UsersPage } from "./pages/Users";
import { ErrorBox } from "./ui";

type Session = { state: "loading" } | { state: "signed-out" } | { state: "error"; error: unknown } | { state: "signed-in"; me: Me };

export function App() {
  const [session, setSession] = useState<Session>({ state: "loading" });

  const loadMe = useCallback(async () => {
    try {
      const me = await api<Me>("/auth/me");
      setSession({ state: "signed-in", me });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setSession({ state: "signed-out" });
      else setSession({ state: "error", error: e });
    }
  }, []);

  useEffect(() => {
    setSessionEndedHandler(() => setSession({ state: "signed-out" }));
    void loadMe();
  }, [loadMe]);

  const signOut = async () => {
    try {
      await api("/auth/logout", { method: "POST", noRefresh: true });
    } finally {
      setSession({ state: "signed-out" });
      window.location.hash = "";
    }
  };

  switch (session.state) {
    case "loading":
      return <p className="loading">Loading...</p>;
    case "error":
      return (
        <main className="login">
          <div className="card login-card">
            <h1>APIEdge</h1>
            <ErrorBox error={session.error} />
            <button onClick={() => void loadMe()}>Retry</button>
          </div>
        </main>
      );
    case "signed-out":
      return <Login onSignedIn={() => void loadMe()} />;
    case "signed-in":
      if (session.me.must_change_password) {
        return (
          <main className="login">
            <ChangePassword forced onDone={() => void loadMe()} />
            <button className="link" onClick={() => void signOut()}>Sign out</button>
          </main>
        );
      }
      return <Shell me={session.me} onSignOut={() => void signOut()} onMeChanged={() => void loadMe()} />;
  }
}

function useHash(): string {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

function Shell({ me, onSignOut, onMeChanged }: { me: Me; onSignOut: () => void; onMeChanged: () => void }) {
  const page: Page = pageFromHash(useHash(), me);
  const nav = navFor(me);
  // SuperAdmins pick the tenant to work in; everyone else works in their own tenant.
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<number | null>(me.tenant_id);
  const loadTenants = useCallback(() => {
    if (!me.is_superadmin) return;
    api<Tenant[]>("/tenants")
      .then((ts) => {
        setTenants(ts);
        setTenantId((cur) => (cur !== null && ts.some((t) => t.id === cur) ? cur : (ts[0]?.id ?? null)));
      })
      .catch(() => setTenants([]));
  }, [me.is_superadmin]);
  useEffect(loadTenants, [loadTenants]);

  const current = nav.find((n) => n.page === page);
  const needsTenant = current?.tenantScoped && tenantId === null;

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">APIEdge</span>
        {me.is_superadmin && (
          <label className="tenant-pick">
            <span>Tenant</span>
            <select value={tenantId ?? ""} onChange={(e) => setTenantId(e.target.value ? Number(e.target.value) : null)}>
              {tenants.length === 0 && <option value="">No tenants</option>}
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </label>
        )}
        <span className="spacer" />
        <span className="who">
          {me.username}
          {me.is_superadmin && <span className="badge">SuperAdmin</span>}
        </span>
        <button className="link" onClick={onSignOut}>Sign out</button>
      </header>
      <nav className="sidenav" aria-label="Main">
        {nav.map((n) => (
          <a key={n.page} href={`#/${n.page}`} className={n.page === page ? "active" : ""} aria-current={n.page === page ? "page" : undefined}>
            {n.label}
          </a>
        ))}
      </nav>
      <main className="content">
        {needsTenant ? (
          <p className="muted">Create a tenant first (Tenants page).</p>
        ) : (
          <PageView page={page} me={me} tenantId={tenantId} onMeChanged={onMeChanged} onTenantsChanged={loadTenants} />
        )}
      </main>
    </div>
  );
}

function PageView(props: { page: Page; me: Me; tenantId: number | null; onMeChanged: () => void; onTenantsChanged: () => void }) {
  const { page, me, tenantId } = props;
  switch (page) {
    case "tenants":
      return <TenantsPage me={me} onChanged={props.onTenantsChanged} />;
    case "products":
      return tenantId === null ? null : <ProductsPage key={tenantId} me={me} tenantId={tenantId} />;
    case "analytics":
      return tenantId === null ? null : <AnalyticsPage key={tenantId} tenantId={tenantId} />;
    case "users":
      return tenantId === null ? null : <UsersPage key={tenantId} me={me} tenantId={tenantId} />;
    case "roles":
      return tenantId === null ? null : <RolesPage key={tenantId} me={me} tenantId={tenantId} />;
    case "audit":
      return <AuditPage key={tenantId ?? 0} me={me} tenantId={tenantId} />;
    case "settings":
      return <SettingsPage />;
    case "account":
      return <AccountPage me={me} onChanged={props.onMeChanged} />;
  }
}
