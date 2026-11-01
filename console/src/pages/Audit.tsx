// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import type { AuditEvent, Me } from "../types";
import { Card, ErrorBox, fmtDate, useAction } from "../ui";

const PAGE = 50;

/** Audit log of the selected tenant, or of the whole platform for SuperAdmins. */
export function AuditPage({ me, tenantId }: { me: Me; tenantId: number | null }) {
  const [platform, setPlatform] = useState(me.is_superadmin && tenantId === null);
  const [filter, setFilter] = useState("");
  const [applied, setApplied] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [more, setMore] = useState(false);
  const action = useAction();
  const scope = platform || tenantId === null ? "platform" : `tenant:${tenantId}`;

  const load = async (before: number | null) => {
    const q = new URLSearchParams({ limit: String(PAGE) });
    if (before !== null) q.set("before_id", String(before));
    if (applied) q.set("action", applied);
    const path = scope === "platform" ? `/audit?${q}` : `/tenants/${tenantId}/audit?${q}`;
    await action.run(async () => {
      const page = await api<AuditEvent[]>(path);
      setEvents((prev) => (before === null ? page : [...prev, ...page]));
      setMore(page.length === PAGE);
    });
  };

  useEffect(() => {
    void load(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, applied]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setApplied(filter.trim());
  };

  return (
    <Card title="Audit log">
      <form className="row" onSubmit={submit}>
        <label className="field">
          <span>Action (exact, e.g. auth.login)</span>
          <input value={filter} onChange={(e) => setFilter(e.target.value)} maxLength={64} />
        </label>
        <button type="submit">Filter</button>
        {me.is_superadmin && tenantId !== null && (
          <label className="check">
            <input type="checkbox" checked={platform} onChange={(e) => setPlatform(e.target.checked)} />
            All tenants
          </label>
        )}
      </form>
      <ErrorBox error={action.error} />
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Outcome</th>
            <th>Client</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev) => (
            <tr key={ev.id}>
              <td>{fmtDate(ev.created_at)}</td>
              <td>{ev.actor_username ?? "-"}</td>
              <td><code>{ev.action}</code></td>
              <td>{ev.resource_type ? `${ev.resource_type} ${ev.resource_id ?? ""}` : "-"}</td>
              <td className={ev.outcome === "success" ? "" : "bad"}>{ev.outcome}</td>
              <td>{ev.client_ip ?? "-"}</td>
              <td className="small">{ev.details ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!action.busy && events.length === 0 && <p className="muted">No events.</p>}
      {more && (
        <button disabled={action.busy} onClick={() => void load(events[events.length - 1]?.id ?? null)}>
          Load older events
        </button>
      )}
    </Card>
  );
}
