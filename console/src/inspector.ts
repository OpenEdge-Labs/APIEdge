// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Pure helpers for the Packet inspector page (T-012): filter query strings, the live list,
// body display and capture-form validation. Kept free of React so they can be unit-tested.
import type { CapturedBody, CaptureSession, ExchangeSummary } from "./types";

export interface ExchangeFilters {
  sessionId: number | null;
  method: string;
  statusClass: number | null; // 1..5 (1xx..5xx)
  path: string;
  consumer: string;
}

export const EMPTY_FILTERS: ExchangeFilters = { sessionId: null, method: "", statusClass: null, path: "", consumer: "" };

/** Query string for the exchange list and the live stream. */
export function exchangeQuery(f: ExchangeFilters, extra: Record<string, string | number> = {}): string {
  const q = new URLSearchParams();
  if (f.sessionId !== null) q.set("session_id", String(f.sessionId));
  if (f.method.trim()) q.set("method", f.method.trim().toUpperCase());
  if (f.statusClass !== null) q.set("status_class", String(f.statusClass));
  if (f.path.trim()) q.set("path", f.path.trim());
  if (f.consumer.trim()) q.set("consumer", f.consumer.trim());
  for (const [k, v] of Object.entries(extra)) q.set(k, String(v));
  return q.toString();
}

/** Adds live exchanges to the list: newest first, no duplicates, at most `max` rows. */
export function mergeExchanges(current: ExchangeSummary[], incoming: ExchangeSummary[], max = 200): ExchangeSummary[] {
  const byId = new Map<number, ExchangeSummary>();
  for (const e of [...incoming, ...current]) if (!byId.has(e.id)) byId.set(e.id, e);
  return [...byId.values()].sort((a, b) => b.id - a.id).slice(0, max);
}

/** Text to show for a captured body. */
export function bodyText(body: CapturedBody | undefined): string {
  if (!body || !body.captured) return "(not captured: the gateway did not read this body)";
  if (body.size === 0) return "(empty)";
  const note = body.truncated ? `\n... (${body.size} bytes in total, only the first part was captured)` : "";
  if (body.encoding === "base64") return `(binary, ${body.size} bytes, base64)\n${body.text}${note}`;
  return prettyJson(body.text) + note;
}

/** Pretty-prints JSON text; anything else is returned unchanged. */
export function prettyJson(text: string): string {
  const t = text.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return text;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return text;
  }
}

/** "4m 05s left" / "ended". */
export function remaining(s: CaptureSession, now: Date): string {
  if (s.state !== "active") return s.state;
  const end = new Date(s.expires_at.endsWith("Z") || s.expires_at.includes("+") ? s.expires_at : `${s.expires_at}Z`);
  const secs = Math.max(0, Math.round((end.getTime() - now.getTime()) / 1000));
  const m = Math.floor(secs / 60);
  return `${m}m ${String(secs % 60).padStart(2, "0")}s left`;
}

export interface CaptureForm {
  productId: number | null;
  apiId: number | null;
  route: string;
  consumer: string;
  duration: string;
  maxExchanges: string;
  maxBody: string;
  maskFields: string;
}

export const FIELD_NAME = /^[A-Za-z0-9_.-]{1,100}$/;

export function parseMaskFields(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))];
}

export function captureErrors(f: CaptureForm): string[] {
  const errors: string[] = [];
  if (f.apiId === null) errors.push("Choose an API.");
  const int = (v: string, min: number, max: number, label: string) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) errors.push(`${label} must be a whole number from ${min} to ${max}.`);
  };
  int(f.duration, 1, 1440, "Duration (minutes)");
  int(f.maxExchanges, 1, 100000, "Max exchanges");
  int(f.maxBody, 0, 1048576, "Max body bytes");
  const bad = parseMaskFields(f.maskFields).filter((n) => !FIELD_NAME.test(n));
  if (bad.length) errors.push(`Invalid field names: ${bad.join(", ")}`);
  return errors;
}

export function captureBody(f: CaptureForm) {
  return {
    api_id: f.apiId,
    route: f.route || null,
    consumer: f.consumer.trim() === "" ? null : f.consumer.trim(),
    duration_minutes: Number(f.duration),
    max_exchanges: Number(f.maxExchanges),
    max_body_bytes: Number(f.maxBody),
    mask_fields: parseMaskFields(f.maskFields),
  };
}
