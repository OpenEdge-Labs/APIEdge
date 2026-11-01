// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Policy chain editor of one API (T-008): ordered, form-based policies with route scoping.
// Read-only without policy:update (the server checks every call itself).
import { useEffect, useState } from "react";
import { api } from "../api";
import { POLICY_TYPES, chainBody, formFromSpec, move, newPolicy, typeInfo, type FieldDef, type PolicyChain, type PolicyForm, type PolicyType } from "../policies";
import type { Api } from "../types";
import { Card, ErrorBox, Notice, useAction, useLoad } from "../ui";

export function PoliciesEditor(props: { base: string; api: Api; readOnly: boolean; onClose: () => void }) {
  const url = `${props.base}/${props.api.id}/policies`;
  const chain = useLoad(() => api<PolicyChain>(url), [url]);
  const [forms, setForms] = useState<PolicyForm[]>([]);
  const [adding, setAdding] = useState<PolicyType>("api-key");
  const [problems, setProblems] = useState<string[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();
  const routes = props.api.routes.map((r) => r.path);
  const secretsSet = chain.data?.secrets_set ?? {};

  useEffect(() => {
    if (chain.data) setForms(chain.data.policies.map(formFromSpec));
  }, [chain.data]);

  const update = (i: number, patch: Partial<PolicyForm>) => setForms((fs) => fs.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  const setValue = (i: number, key: string, value: PolicyForm["values"][string]) =>
    setForms((fs) => fs.map((f, j) => (j === i ? { ...f, values: { ...f.values, [key]: value } } : f)));

  const save = async () => {
    setNotice(null);
    const { body, errors } = chainBody(forms);
    setProblems(errors);
    if (!body) return;
    if (await action.run(async () => {
      const saved = await api<PolicyChain>(url, { method: "PUT", body });
      chain.setData(saved);
    })) setNotice("Policies saved. The gateway applies them within moments.");
  };

  return (
    <Card title={`Policies of ${props.api.name} ${props.api.version}`} actions={<button onClick={props.onClose}>Close</button>}>
      <p className="hint">
        Policies run top to bottom on each request; a policy that rejects or answers a request stops the chain, and the
        response passes back through the policies that ran. Limit a policy to some routes, or leave all unticked for every route.
      </p>
      <ErrorBox error={chain.error || action.error} />
      <Notice text={notice} />
      {forms.length === 0 && chain.data && <p className="muted">No policies: requests go straight to the upstream.</p>}
      <fieldset className="plain" disabled={props.readOnly || action.busy}>
        {forms.map((f, i) => (
          <div key={f.id ?? `new-${i}`} className="policy">
            <div className="policy-head">
              <strong>
                {i + 1}. {typeInfo(f.type).label}
              </strong>
              {f.id && <code className="muted small">{f.id}</code>}
              <label className="check">
                <input type="checkbox" checked={f.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} />
                Enabled
              </label>
              <span className="actions">
                <button type="button" aria-label="Move up" disabled={i === 0} onClick={() => setForms(move(forms, i, i - 1))}>Up</button>
                <button type="button" aria-label="Move down" disabled={i === forms.length - 1} onClick={() => setForms(move(forms, i, i + 1))}>Down</button>
                <button type="button" className="danger" onClick={() => setForms(forms.filter((_, j) => j !== i))}>Remove</button>
              </span>
            </div>
            <p className="hint">{typeInfo(f.type).summary}</p>
            <div className="row">
              <label className="field">
                <span>Name (optional)</span>
                <input value={f.name} maxLength={100} onChange={(e) => update(i, { name: e.target.value })} />
              </label>
            </div>
            {routes.length > 0 && (
              <div className="field wide">
                <span>Routes</span>
                <div>
                  {routes.map((r) => (
                    <label key={r} className="check">
                      <input
                        type="checkbox"
                        checked={f.routes.includes(r)}
                        onChange={() => update(i, { routes: f.routes.includes(r) ? f.routes.filter((x) => x !== r) : [...f.routes, r] })}
                      />
                      <code>{r}</code>
                    </label>
                  ))}
                  {f.routes.filter((r) => !routes.includes(r)).map((r) => (
                    <span key={r} className="error small"> {r} (no longer a route)</span>
                  ))}
                </div>
              </div>
            )}
            <div className="policy-fields">
              {typeInfo(f.type).fields.map((field) => (
                <PolicyField
                  key={field.key}
                  field={field}
                  value={f.values[field.key]}
                  stored={!!f.id && (secretsSet[f.id] ?? []).includes(field.key)}
                  onChange={(v) => setValue(i, field.key, v)}
                />
              ))}
            </div>
          </div>
        ))}
        {!props.readOnly && (
          <div className="row">
            <label className="field">
              <span>Add a policy</span>
              <select value={adding} onChange={(e) => setAdding(e.target.value as PolicyType)}>
                {POLICY_TYPES.map((t) => (
                  <option key={t.type} value={t.type}>{t.label}</option>
                ))}
              </select>
            </label>
            <button type="button" onClick={() => setForms([...forms, newPolicy(adding)])}>Add</button>
          </div>
        )}
      </fieldset>
      {problems.length > 0 && (
        <ul className="error" role="alert">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {!props.readOnly && (
        <div className="row">
          <button type="button" className="primary" disabled={action.busy || !chain.data} onClick={() => void save()}>Save policies</button>
          <button type="button" disabled={action.busy} onClick={() => chain.data && setForms(chain.data.policies.map(formFromSpec))}>Discard changes</button>
        </div>
      )}
    </Card>
  );
}

function PolicyField(props: { field: FieldDef; value: PolicyForm["values"][string]; stored: boolean; onChange: (v: PolicyForm["values"][string]) => void }) {
  const { field, value, onChange } = props;
  const text = typeof value === "string" ? value : "";
  if (field.kind === "bool") {
    return (
      <label className="check wide">
        <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} />
        {field.label}
      </label>
    );
  }
  if (field.kind === "multi") {
    const selected = Array.isArray(value) ? value : [];
    return (
      <div className="field wide">
        <span>{field.label}</span>
        <div>
          {(field.options ?? []).map((o) => (
            <label key={o} className="check">
              <input
                type="checkbox"
                checked={selected.includes(o)}
                onChange={() => onChange(selected.includes(o) ? selected.filter((x) => x !== o) : [...selected, o])}
              />
              {o}
            </label>
          ))}
        </div>
        {field.hint && <span className="hint">{field.hint}</span>}
      </div>
    );
  }
  if (field.kind === "select") {
    return (
      <label className="field">
        <span>{field.label}</span>
        <select value={text} onChange={(e) => onChange(e.target.value)}>
          {(field.options ?? []).map((o) => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>
        {field.hint && <span className="hint">{field.hint}</span>}
      </label>
    );
  }
  const multiline = field.kind === "lines" || field.kind === "pairs" || field.kind === "json-pairs" || field.kind === "textarea";
  return (
    <label className={multiline ? "field wide" : "field"}>
      <span>{field.label}</span>
      {multiline ? (
        <textarea rows={3} value={text} placeholder={field.placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
      ) : (
        <input
          type={field.kind === "secret" ? "password" : "text"}
          autoComplete={field.kind === "secret" ? "new-password" : "off"}
          inputMode={field.kind === "number" ? "numeric" : "text"}
          value={text}
          placeholder={field.kind === "secret" && props.stored ? "stored - leave empty to keep" : field.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {field.hint && <span className="hint">{field.hint}</span>}
    </label>
  );
}
