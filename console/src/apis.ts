// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Form model and checks for the no-code API editor (T-006). They mirror the server's rules so
// mistakes show up before saving; the server validates everything again (including the SSRF guard
// on upstream URLs, which only the server can apply).
import type { Api, HttpMethod } from "./types";

export const METHODS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const SEGMENT = "[A-Za-z0-9_.~-]+";
const PARAM = "\\{[A-Za-z_][A-Za-z0-9_]{0,63}\\}";
const BASE_PATH = new RegExp(`^(/${SEGMENT})+$`);
const ROUTE_PATH = new RegExp(`^/(\\*|(${SEGMENT}|${PARAM})(/(${SEGMENT}|${PARAM}))*(/\\*)?)?$`);
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const RESERVED = ["/api/v1", "/healthz", "/readyz", "/docs", "/redoc", "/openapi.json", "/assets"];

export interface UpstreamRow {
  url: string;
  weight: string;
}

export interface RouteRow {
  methods: HttpMethod[];
  path: string;
  description: string;
}

export interface ApiForm {
  name: string;
  version: string;
  base_path: string;
  description: string;
  timeout_ms: string;
  upstreams: UpstreamRow[];
  routes: RouteRow[];
}

export function emptyForm(): ApiForm {
  return {
    name: "",
    version: "v1",
    base_path: "",
    description: "",
    timeout_ms: "30000",
    upstreams: [{ url: "", weight: "1" }],
    routes: [{ methods: ["GET"], path: "/*", description: "" }],
  };
}

export function formFromApi(a: Api): ApiForm {
  return {
    name: a.name,
    version: a.version,
    base_path: a.base_path,
    description: a.description,
    timeout_ms: String(a.timeout_ms),
    upstreams: a.upstreams.map((u) => ({ url: u.url, weight: String(u.weight) })),
    routes: a.routes.map((r) => ({ methods: [...r.methods], path: r.path, description: r.description })),
  };
}

function dotSegments(path: string): boolean {
  return path.split("/").some((s) => s === "." || s === "..");
}

export function basePathError(path: string): string | null {
  if (!BASE_PATH.test(path) || path.length > 255) {
    return "Base path: start with / and use letters, digits and - _ . ~ (for example /orders/v1).";
  }
  if (dotSegments(path)) return "Base path: '.' and '..' segments are not allowed.";
  const low = path.toLowerCase();
  const hit = RESERVED.find((p) => low === p || low.startsWith(`${p}/`));
  return hit ? `Base path: ${hit} is reserved by APIEdge.` : null;
}

export function routePathError(path: string): string | null {
  if (!ROUTE_PATH.test(path) || path.length > 500 || dotSegments(path)) {
    return `Route path "${path}": start with /, use {name} for parameters and end with /* for a prefix.`;
  }
  const params = path.split("/").filter((s) => s.startsWith("{"));
  return new Set(params).size === params.length ? null : `Route path "${path}": parameter names must be unique.`;
}

/** Erases parameter names: /a/{id} and /a/{x} match the same requests. */
export function routeKey(path: string): string {
  return path
    .split("/")
    .map((s) => (s.startsWith("{") ? "{}" : s))
    .join("/");
}

/** Rows the user left completely empty are ignored. */
function filledUpstreams(f: ApiForm): UpstreamRow[] {
  return f.upstreams.filter((u) => u.url.trim() !== "");
}

function filledRoutes(f: ApiForm): RouteRow[] {
  return f.routes.filter((r) => r.path.trim() !== "");
}

/** Client-side checks; an empty list means the form can be sent. */
export function formErrors(f: ApiForm): string[] {
  const errors: string[] = [];
  if (!f.name.trim()) errors.push("Name is required.");
  if (!VERSION.test(f.version)) errors.push("Version: letters, digits and . _ - (up to 32 characters).");
  const base = basePathError(f.base_path);
  if (base) errors.push(base);
  const timeout = Number(f.timeout_ms);
  if (!Number.isInteger(timeout) || timeout < 100 || timeout > 300000) {
    errors.push("Timeout: a whole number of milliseconds from 100 to 300000.");
  }
  filledUpstreams(f).forEach((u, i) => {
    if (!/^https?:\/\//i.test(u.url.trim())) errors.push(`Upstream ${i + 1}: use an http:// or https:// URL.`);
    const w = Number(u.weight);
    if (!Number.isInteger(w) || w < 1 || w > 100) errors.push(`Upstream ${i + 1}: weight must be 1 to 100.`);
  });
  const seen = new Map<string, string>();
  for (const r of filledRoutes(f)) {
    const err = routePathError(r.path.trim());
    if (err) errors.push(err);
    if (r.methods.length === 0) errors.push(`Route ${r.path}: pick at least one method.`);
    for (const m of r.methods) {
      const key = `${m} ${routeKey(r.path.trim())}`;
      const prev = seen.get(key);
      if (prev !== undefined) errors.push(`${m} ${r.path} overlaps ${m} ${prev}.`);
      else seen.set(key, r.path);
    }
  }
  return errors;
}

/** The request body for create (POST) or update (PATCH). */
export function toBody(f: ApiForm) {
  return {
    name: f.name.trim(),
    version: f.version.trim(),
    base_path: f.base_path.trim(),
    description: f.description,
    timeout_ms: Number(f.timeout_ms),
    upstreams: filledUpstreams(f).map((u) => ({ url: u.url.trim(), weight: Number(u.weight) })),
    routes: filledRoutes(f).map((r) => ({
      methods: METHODS.filter((m) => r.methods.includes(m)),
      path: r.path.trim(),
      description: r.description,
    })),
  };
}
