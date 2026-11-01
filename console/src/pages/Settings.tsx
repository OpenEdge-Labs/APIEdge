// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { api } from "../api";
import type { Setting } from "../types";
import { Card, ErrorBox, useLoad } from "../ui";

/** Read-only view of the effective configuration (set through APIEDGE_* environment variables). */
export function SettingsPage() {
  const { data, error } = useLoad(() => api<Setting[]>("/system/settings"), []);
  const groups = new Map<string, Setting[]>();
  for (const s of data ?? []) groups.set(s.group, [...(groups.get(s.group) ?? []), s]);
  return (
    <Card title="System settings">
      <p className="muted">
        Settings come from <code>APIEDGE_*</code> environment variables or the <code>.env</code> file and take effect
        after a restart. Secrets are never shown. See the Administrator Guide, configuration chapter.
      </p>
      <ErrorBox error={error} />
      {[...groups.entries()].map(([group, rows]) => (
        <div key={group}>
          <h3>{group}</h3>
          <table>
            <tbody>
              {rows.map((s) => (
                <tr key={s.name}>
                  <td><code>APIEDGE_{s.name.toUpperCase()}</code></td>
                  <td>{s.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </Card>
  );
}
