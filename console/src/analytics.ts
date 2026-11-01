// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Pure helpers for the Analytics page (T-013): time ranges, query strings, formatting and the
// chart geometry. Kept free of React so they can be unit-tested.
import type { AnalyticsPoint } from "./types";

export interface RangeOption {
  key: string;
  label: string;
  seconds: number;
}

export const RANGES: RangeOption[] = [
  { key: "15m", label: "Last 15 minutes", seconds: 15 * 60 },
  { key: "1h", label: "Last hour", seconds: 3600 },
  { key: "6h", label: "Last 6 hours", seconds: 6 * 3600 },
  { key: "24h", label: "Last 24 hours", seconds: 86400 },
  { key: "7d", label: "Last 7 days", seconds: 7 * 86400 },
  { key: "30d", label: "Last 30 days", seconds: 30 * 86400 },
];

export interface AnalyticsFilters {
  range: string;
  apiId: number | null;
  consumer: string | null;
}

/** Query string for the summary and export endpoints, relative to `now`. */
export function analyticsQuery(f: AnalyticsFilters, now: Date): string {
  const range = RANGES.find((r) => r.key === f.range) ?? RANGES[1];
  const end = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const start = new Date(end.getTime() - range.seconds * 1000);
  const q = new URLSearchParams({ start: start.toISOString(), end: end.toISOString() });
  if (f.apiId !== null) q.set("api_id", String(f.apiId));
  if (f.consumer !== null) q.set("consumer", f.consumer);
  return q.toString();
}

export function fmtMs(ms: number | null): string {
  if (ms === null) return "-";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
}

export function fmtPct(rate: number): string {
  return `${(rate * 100).toFixed(rate > 0 && rate < 0.01 ? 2 : 1)}%`;
}

export function fmtCount(n: number): string {
  return n.toLocaleString("en-US");
}

export function fmtBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${units[i]}`;
}

export function consumerLabel(consumer: string): string {
  return consumer === "" ? "(anonymous)" : consumer;
}

/** CSS class for a status code family. */
export function statusClass(status: number): string {
  if (status >= 500) return "bad";
  if (status >= 400) return "warn";
  return "";
}

export interface Bar {
  x: number;
  width: number;
  height: number;
  errorHeight: number;
  t: number;
  requests: number;
  errors: number;
}

/**
 * Bars for a traffic chart of `width` x `height` covering [start, end) in `step`-second slots.
 * Slots without data are left empty, so gaps in traffic stay visible.
 */
export function trafficBars(points: AnalyticsPoint[], start: number, end: number, step: number, width: number, height: number): Bar[] {
  const slots = Math.max(1, Math.ceil((end - start) / step));
  const slot = width / slots;
  const max = Math.max(1, ...points.map((p) => p.requests));
  return points.map((p) => {
    const idx = Math.min(slots - 1, Math.max(0, Math.floor((p.t - start) / step)));
    const h = (p.requests / max) * height;
    return {
      x: idx * slot,
      width: Math.max(1, slot * 0.8),
      height: h,
      errorHeight: p.requests ? (p.errors / p.requests) * h : 0,
      t: p.t,
      requests: p.requests,
      errors: p.errors,
    };
  });
}

/** Polyline points (SVG `points` attribute) for a latency series, scaled to `max`. */
export function latencyLine(
  points: AnalyticsPoint[],
  start: number,
  end: number,
  step: number,
  width: number,
  height: number,
  max: number,
): string {
  const slots = Math.max(1, Math.ceil((end - start) / step));
  const slot = width / slots;
  return points
    .filter((p) => p.latency_p95_ms !== null)
    .map((p) => {
      const idx = Math.min(slots - 1, Math.max(0, Math.floor((p.t - start) / step)));
      const y = height - (Math.min(p.latency_p95_ms ?? 0, max) / Math.max(max, 1)) * height;
      return `${(idx * slot + slot * 0.4).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}
