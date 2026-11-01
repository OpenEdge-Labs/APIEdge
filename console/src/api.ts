// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Thin client for the admin API (/api/v1). The browser session lives in HttpOnly cookies; unsafe
// requests echo the readable apiedge_csrf cookie in X-CSRF-Token (double-submit, T-002).

export const API_BASE = "/api/v1";
const CSRF_COOKIE = "apiedge_csrf";
const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: unknown,
  ) {
    super(describeDetail(detail) || `HTTP ${status}`);
  }

  /** The short machine code in `detail` (for example `mfa_required`), if there is one. */
  get code(): string | undefined {
    return typeof this.detail === "string" ? this.detail : undefined;
  }
}

const MESSAGES: Record<string, string> = {
  invalid_credentials: "Wrong username or password.",
  account_locked: "This account is locked. Try again later or ask an administrator to unlock it.",
  mfa_required: "Enter the 6-digit code from your authenticator app.",
  invalid_mfa_code: "That authenticator code is not valid.",
  too_many_attempts: "Too many attempts. Wait a minute and try again.",
  invalid_token: "Your session has ended. Sign in again.",
  not_authenticated: "Sign in to continue.",
  password_change_required: "You must change your password first.",
  permission_denied: "You do not have permission to do that.",
};

/** Turns a FastAPI `detail` (string, list of validation errors or object) into readable text. */
export function describeDetail(detail: unknown): string {
  if (typeof detail === "string") return MESSAGES[detail] ?? detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (d && typeof d === "object" && "msg" in d) {
          const loc = Array.isArray((d as { loc?: unknown }).loc)
            ? ((d as { loc: unknown[] }).loc.filter((p) => p !== "body").join("."))
            : "";
          return loc ? `${loc}: ${String((d as { msg: unknown }).msg)}` : String((d as { msg: unknown }).msg);
        }
        return String(d);
      })
      .join("; ");
  }
  if (detail && typeof detail === "object") {
    return Object.entries(detail as Record<string, unknown>)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`)
      .join("; ");
  }
  return "";
}

export function readCookie(
  name: string,
  cookieString: string = typeof document === "undefined" ? "" : document.cookie,
): string | undefined {
  for (const part of cookieString.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

export interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Internal: do not try a refresh on 401 (used by the auth calls themselves). */
  noRefresh?: boolean;
}

/** Called when the session cannot be renewed; the app returns to the sign-in screen. */
let onSessionEnded: () => void = () => undefined;
export function setSessionEndedHandler(fn: () => void): void {
  onSessionEnded = fn;
}

let fetcher: Fetcher = (input, init) => fetch(input, init);
export function setFetcher(fn: Fetcher): void {
  fetcher = fn;
}

let refreshing: Promise<boolean> | null = null;

async function send(path: string, opts: RequestOptions, accept = "application/json"): Promise<Response> {
  const method = (opts.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { Accept: accept };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (!SAFE.has(method)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  return fetcher(API_BASE + path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = send("/auth/refresh", { method: "POST" })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  }
  return refreshing;
}

/** Calls the admin API; renews the session once on 401 and throws {@link ApiError} on failure. */
export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await request(path, opts);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Downloads a file (e.g. a CSV export) from the admin API with the same session handling. */
export async function apiFile(path: string, accept: string): Promise<Blob> {
  const res = await request(path, {}, accept);
  return res.blob();
}

async function request(path: string, opts: RequestOptions, accept?: string): Promise<Response> {
  let res = await send(path, opts, accept);
  if (res.status === 401 && !opts.noRefresh) {
    if (await tryRefresh()) {
      res = await send(path, opts, accept);
    }
    if (res.status === 401) onSessionEnded();
  }
  if (!res.ok) {
    let detail: unknown = undefined;
    try {
      detail = ((await res.json()) as { detail?: unknown }).detail;
    } catch {
      detail = undefined;
    }
    throw new ApiError(res.status, detail);
  }
  return res;
}

export function errorText(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Unexpected error.";
}
