// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Form model for the policy chain editor (T-008). Each policy type is described by field
// definitions; the editor renders them generically and converts between the form (strings,
// one item per line) and the admin API's JSON. The server validates everything again.

export type PolicyType = "api-key" | "jwt" | "rate-limit" | "transform" | "cors" | "ip-filter" | "cache" | "mock" | "mtls";

export interface PolicySpec {
  id?: string | null;
  type: PolicyType;
  name: string;
  enabled: boolean;
  routes: string[];
  config: Record<string, unknown>;
}

export interface PolicyChain {
  policies: PolicySpec[];
  secrets_set: Record<string, string[]>;
}

type FieldKind = "text" | "number" | "bool" | "lines" | "pairs" | "json-pairs" | "textarea" | "select" | "multi" | "secret";

export interface FieldDef {
  key: string;
  label: string;
  kind: FieldKind;
  /** Location in `config`, e.g. ["request", "set_headers"]. Defaults to [key]. */
  path?: string[];
  hint?: string;
  options?: string[];
  placeholder?: string;
  /** "pairs": the separator between name and value. */
  sep?: string;
}

export interface PolicyForm {
  id?: string | null;
  type: PolicyType;
  name: string;
  enabled: boolean;
  routes: string[];
  values: Record<string, string | boolean | string[]>;
}

const HTTP = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
export const JWT_ALGS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

function transformFields(phase: "request" | "response"): FieldDef[] {
  const p = (k: string) => [phase, k];
  const fields: FieldDef[] = [
    { key: `${phase}.set_headers`, path: p("set_headers"), label: `Set ${phase} headers`, kind: "pairs", sep: ":", placeholder: "x-consumer: {consumer}" },
    { key: `${phase}.remove_headers`, path: p("remove_headers"), label: `Remove ${phase} headers`, kind: "lines", placeholder: "x-internal-debug" },
    { key: `${phase}.set_json`, path: p("set_json"), label: `Set JSON fields (${phase} body)`, kind: "json-pairs", placeholder: 'meta.source = "gateway"' },
    { key: `${phase}.remove_json`, path: p("remove_json"), label: `Remove JSON fields (${phase} body)`, kind: "lines", placeholder: "password" },
  ];
  if (phase === "request") {
    fields.push(
      { key: "request.set_query", path: ["request", "set_query"], label: "Set query parameters", kind: "pairs", sep: "=", placeholder: "version=2" },
      { key: "request.remove_query", path: ["request", "remove_query"], label: "Remove query parameters", kind: "lines", placeholder: "debug" },
    );
  } else {
    fields.push({ key: "response.max_body_bytes", path: ["response", "max_body_bytes"], label: "Largest response body to transform (bytes)", kind: "number" });
  }
  return fields;
}

export const POLICY_TYPES: { type: PolicyType; label: string; summary: string; fields: FieldDef[] }[] = [
  {
    type: "api-key",
    label: "API key",
    summary: "Requires a valid API key of this product (create keys under API keys).",
    fields: [
      { key: "header", label: "Header", kind: "text", placeholder: "x-api-key" },
      { key: "query_param", label: "Query parameter (optional, discouraged: URLs end up in logs)", kind: "text" },
      { key: "hide_credentials", label: "Do not forward the key to the upstream", kind: "bool" },
    ],
  },
  {
    type: "jwt",
    label: "JWT validation",
    summary: "Requires a signed JSON Web Token (bearer token) and checks its claims.",
    fields: [
      { key: "algorithms", label: "Allowed algorithms", kind: "multi", options: JWT_ALGS, hint: "Use HS* (shared secret) or RS/PS/ES (public key or JWKS), not both." },
      { key: "builtin_issuer", label: "Built-in issuer: tokens of this tenant's OAuth server (RS256; leave keys, JWKS and issuer empty)", kind: "bool" },
      { key: "secret", label: "Shared secret (HS*, at least 32 bytes)", kind: "secret" },
      { key: "public_key", label: "Public key (PEM)", kind: "textarea", placeholder: "-----BEGIN PUBLIC KEY-----" },
      { key: "jwks_url", label: "JWKS URL (https)", kind: "text", placeholder: "https://idp.example.com/.well-known/jwks.json" },
      { key: "jwks_cache_seconds", label: "JWKS cache (seconds)", kind: "number" },
      { key: "issuer", label: "Issuer (iss)", kind: "text" },
      { key: "audiences", label: "Audiences (aud), one per line", kind: "lines" },
      { key: "require_exp", label: "Require an expiry (exp)", kind: "bool" },
      { key: "leeway_seconds", label: "Clock leeway (seconds)", kind: "number" },
      { key: "header", label: "Header", kind: "text", placeholder: "authorization" },
      { key: "consumer_claim", label: "Consumer claim", kind: "text", placeholder: "sub" },
      { key: "hide_credentials", label: "Do not forward the token to the upstream", kind: "bool" },
    ],
  },
  {
    type: "rate-limit",
    label: "Rate limit / quota",
    summary: "Answers 429 with Retry-After once the limit for the window is used up.",
    fields: [
      { key: "limit", label: "Requests per window", kind: "number" },
      { key: "window_seconds", label: "Window (seconds; 86400 = daily quota)", kind: "number" },
      { key: "key_by", label: "Count per", kind: "select", options: ["consumer", "ip", "api"], hint: "consumer falls back to the client address for anonymous calls" },
    ],
  },
  {
    type: "transform",
    label: "Header / body transform",
    summary: "Changes headers, query parameters and JSON body fields. Placeholders: {consumer}, {request_id}, {client_ip}.",
    fields: [...transformFields("request"), ...transformFields("response")],
  },
  {
    type: "cors",
    label: "CORS",
    summary: "Answers browser preflights and adds CORS headers for allowed origins. Put it first in the chain.",
    fields: [
      { key: "allow_origins", label: "Allowed origins, one per line (* for any)", kind: "lines", placeholder: "https://app.example.com" },
      { key: "allow_methods", label: "Allowed methods", kind: "multi", options: HTTP },
      { key: "allow_headers", label: "Allowed request headers, one per line (* for any)", kind: "lines" },
      { key: "expose_headers", label: "Exposed response headers, one per line", kind: "lines" },
      { key: "allow_credentials", label: "Allow credentials (cookies)", kind: "bool" },
      { key: "max_age_seconds", label: "Preflight cache (seconds)", kind: "number" },
    ],
  },
  {
    type: "ip-filter",
    label: "IP allow / deny",
    summary: "Denied addresses always lose; with an allow list only listed addresses get through.",
    fields: [
      { key: "allow", label: "Allow (addresses or CIDR ranges, one per line)", kind: "lines", placeholder: "203.0.113.0/24" },
      { key: "deny", label: "Deny (addresses or CIDR ranges, one per line)", kind: "lines" },
    ],
  },
  {
    type: "cache",
    label: "Response cache",
    summary: "Caches GET and HEAD answers that allow it. Requests with credentials bypass it unless enabled below.",
    fields: [
      { key: "ttl_seconds", label: "Time to live (seconds)", kind: "number" },
      { key: "max_entry_bytes", label: "Largest cached response (bytes)", kind: "number" },
      { key: "vary_headers", label: "Also vary on request headers, one per line", kind: "lines" },
      { key: "cache_authenticated", label: "Cache answers to authenticated requests (separately per caller)", kind: "bool" },
    ],
  },
  {
    type: "mock",
    label: "Mock response",
    summary: "Answers with a fixed response; the upstream is not called.",
    fields: [
      { key: "status", label: "Status", kind: "number" },
      { key: "content_type", label: "Content type", kind: "text" },
      { key: "headers", label: "Headers", kind: "pairs", sep: ":" },
      { key: "body", label: "Body", kind: "textarea" },
    ],
  },
  {
    type: "mtls",
    label: "Client certificate (mTLS)",
    summary: "Requires a client certificate issued by a CA in one of this tenant's truststores (TLS page).",
    fields: [
      { key: "truststore_id", label: "Truststore id", kind: "number", hint: "Shown on the TLS page." },
      { key: "allowed_subjects", label: "Allowed subjects or common names, one per line (optional)", kind: "lines", placeholder: "billing-svc" },
      { key: "allowed_fingerprints", label: "Allowed SHA-256 fingerprints, one per line (optional)", kind: "lines" },
      { key: "consumer_from", label: "Consumer name from", kind: "select", options: ["common_name", "subject", "fingerprint"] },
      { key: "forward_subject_header", label: "Send the verified subject to the upstream in header (optional)", kind: "text", placeholder: "x-client-subject" },
    ],
  },
];

export function typeInfo(type: PolicyType) {
  const info = POLICY_TYPES.find((t) => t.type === type);
  if (!info) throw new Error(`unknown policy type ${type}`);
  return info;
}

const DEFAULTS: Record<PolicyType, Record<string, unknown>> = {
  "api-key": { header: "x-api-key", hide_credentials: true },
  jwt: { algorithms: ["RS256"], require_exp: true, leeway_seconds: 30, jwks_cache_seconds: 300, header: "authorization", consumer_claim: "sub" },
  "rate-limit": { limit: 100, window_seconds: 60, key_by: "consumer" },
  transform: {},
  cors: { allow_origins: [], allow_methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], max_age_seconds: 600 },
  "ip-filter": {},
  cache: { ttl_seconds: 60, max_entry_bytes: 1048576 },
  mock: { status: 200, content_type: "application/json", body: '{"message": "mocked"}' },
  mtls: { consumer_from: "common_name" },
};

function getPath(obj: Record<string, unknown>, path: string[]): unknown {
  let node: unknown = obj;
  for (const p of path) {
    if (!node || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[p];
  }
  return node;
}

function setPath(obj: Record<string, unknown>, path: string[], value: unknown): void {
  let node = obj;
  for (const p of path.slice(0, -1)) {
    if (!node[p] || typeof node[p] !== "object") node[p] = {};
    node = node[p] as Record<string, unknown>;
  }
  node[path[path.length - 1]] = value;
}

function toText(field: FieldDef, value: unknown): string | boolean | string[] {
  switch (field.kind) {
    case "bool":
      return value === true;
    case "multi":
      return Array.isArray(value) ? value.map(String) : [];
    case "lines":
      return Array.isArray(value) ? value.join("\n") : "";
    case "pairs":
      return value && typeof value === "object"
        ? Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k}${field.sep === ":" ? ": " : "="}${String(v)}`).join("\n")
        : "";
    case "json-pairs":
      return value && typeof value === "object"
        ? Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join("\n")
        : "";
    case "secret":
      return "";
    default:
      return value === undefined || value === null ? "" : String(value);
  }
}

export function formFromSpec(spec: PolicySpec): PolicyForm {
  const values: PolicyForm["values"] = {};
  for (const f of typeInfo(spec.type).fields) values[f.key] = toText(f, getPath(spec.config, f.path ?? [f.key]));
  return { id: spec.id, type: spec.type, name: spec.name ?? "", enabled: spec.enabled !== false, routes: [...(spec.routes ?? [])], values };
}

export function newPolicy(type: PolicyType): PolicyForm {
  return formFromSpec({ type, name: "", enabled: true, routes: [], config: structuredCloneSafe(DEFAULTS[type]) });
}

function structuredCloneSafe<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

const lines = (text: string) => text.split("\n").map((l) => l.trim()).filter(Boolean);

/** Converts a form back to the API's JSON; returns problems instead when the form is invalid. */
export function specFromForm(form: PolicyForm, index: number): { spec?: PolicySpec; errors: string[] } {
  const errors: string[] = [];
  const label = `Policy ${index + 1} (${typeInfo(form.type).label})`;
  const config: Record<string, unknown> = {};
  for (const f of typeInfo(form.type).fields) {
    const raw = form.values[f.key];
    const path = f.path ?? [f.key];
    switch (f.kind) {
      case "bool":
        setPath(config, path, raw === true);
        break;
      case "multi":
        setPath(config, path, Array.isArray(raw) ? raw : []);
        break;
      case "lines":
        if (lines(String(raw ?? "")).length || path.length === 1) setPath(config, path, lines(String(raw ?? "")));
        break;
      case "pairs":
      case "json-pairs": {
        const out: Record<string, unknown> = {};
        const sep = f.kind === "json-pairs" ? "=" : f.sep ?? ":";
        for (const line of lines(String(raw ?? ""))) {
          const at = line.indexOf(sep);
          if (at <= 0) {
            errors.push(`${label}: "${line}" needs the form name${sep === ":" ? ": " : " = "}value.`);
            continue;
          }
          const name = line.slice(0, at).trim();
          const value = line.slice(at + 1).trim();
          if (f.kind === "json-pairs") {
            try {
              out[name] = JSON.parse(value);
            } catch {
              errors.push(`${label}: the value of ${name} must be JSON (strings in double quotes).`);
            }
          } else {
            out[name] = value;
          }
        }
        if (Object.keys(out).length || path.length === 1) setPath(config, path, out);
        break;
      }
      case "number": {
        const text = String(raw ?? "").trim();
        if (!text) break;
        if (!/^\d+$/.test(text)) errors.push(`${label}: ${f.label} must be a whole number.`);
        else setPath(config, path, Number(text));
        break;
      }
      case "secret": {
        const text = String(raw ?? "");
        setPath(config, path, text ? text : null);
        break;
      }
      default: {
        const text = String(raw ?? "");
        if (f.kind === "textarea" ? text : text.trim()) setPath(config, path, f.kind === "textarea" ? text : text.trim());
        else if (f.kind === "textarea" && form.type === "mock") setPath(config, path, "");
      }
    }
  }
  errors.push(...configErrors(form.type, config, label));
  if (errors.length) return { errors };
  return { spec: { id: form.id ?? null, type: form.type, name: form.name.trim(), enabled: form.enabled, routes: form.routes, config }, errors };
}

const HMAC = new Set(["HS256", "HS384", "HS512"]);

/** Client-side checks that mirror the server's rules (the server checks everything again). */
export function configErrors(type: PolicyType, config: Record<string, unknown>, label: string): string[] {
  const errors: string[] = [];
  if (type === "jwt") {
    const algs = (config.algorithms as string[]) ?? [];
    const hs = algs.filter((a) => HMAC.has(a));
    if (!algs.length) errors.push(`${label}: choose at least one algorithm.`);
    if (hs.length && hs.length !== algs.length) errors.push(`${label}: do not mix HS* with RS*/PS*/ES* algorithms.`);
    if (config.builtin_issuer) {
      if (algs.length !== 1 || algs[0] !== "RS256") errors.push(`${label}: the built-in issuer signs with RS256 only.`);
      if (config.secret || config.public_key || config.jwks_url || config.issuer) errors.push(`${label}: with the built-in issuer, leave the secret, public key, JWKS URL and issuer empty.`);
      return errors;
    }
    if (!hs.length && algs.length && !config.public_key && !config.jwks_url) errors.push(`${label}: give a public key or a JWKS URL.`);
    if (config.public_key && config.jwks_url) errors.push(`${label}: give either a public key or a JWKS URL, not both.`);
    if (typeof config.jwks_url === "string" && !config.jwks_url.toLowerCase().startsWith("https://")) errors.push(`${label}: the JWKS URL must use https.`);
    if (typeof config.secret === "string" && new TextEncoder().encode(config.secret).length < 32) errors.push(`${label}: the shared secret must be at least 32 bytes.`);
  }
  if (type === "cors") {
    const origins = (config.allow_origins as string[]) ?? [];
    if (!origins.length) errors.push(`${label}: list at least one allowed origin.`);
    if (config.allow_credentials && origins.includes("*")) errors.push(`${label}: credentials cannot be allowed for every origin (*).`);
    for (const o of origins) if (o !== "*" && !/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/.test(o)) errors.push(`${label}: "${o}" is not an origin (scheme://host[:port]).`);
  }
  if (type === "ip-filter" && !((config.allow as string[]) ?? []).length && !((config.deny as string[]) ?? []).length) {
    errors.push(`${label}: list at least one allowed or denied address range.`);
  }
  if (type === "mtls" && !config.truststore_id) errors.push(`${label}: choose a truststore (its id from the TLS page).`);
  if (type === "rate-limit" && config.limit === undefined) errors.push(`${label}: set the number of requests per window.`);
  return errors;
}

/** Builds the PUT body for the whole chain, or the list of problems. */
export function chainBody(forms: PolicyForm[]): { body?: { policies: PolicySpec[] }; errors: string[] } {
  const errors: string[] = [];
  const policies: PolicySpec[] = [];
  forms.forEach((f, i) => {
    const r = specFromForm(f, i);
    errors.push(...r.errors);
    if (r.spec) policies.push(r.spec);
  });
  return errors.length ? { errors } : { body: { policies }, errors };
}

export function move<T>(items: T[], from: number, to: number): T[] {
  if (to < 0 || to >= items.length) return items;
  const out = [...items];
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}
