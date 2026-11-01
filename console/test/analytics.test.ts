// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RANGES,
  analyticsQuery,
  consumerLabel,
  fmtBytes,
  fmtMs,
  fmtPct,
  latencyLine,
  statusClass,
  trafficBars,
} from "../src/analytics";
import type { AnalyticsPoint } from "../src/types";

const NOW = new Date("2026-11-01T12:00:00.750Z");

test("the query covers the chosen range up to now and carries the filters", () => {
  const q = new URLSearchParams(analyticsQuery({ range: "24h", apiId: 5, consumer: "" }, NOW));
  assert.equal(q.get("end"), "2026-11-01T12:00:00.000Z");
  assert.equal(q.get("start"), "2026-10-31T12:00:00.000Z");
  assert.equal(q.get("api_id"), "5");
  assert.equal(q.get("consumer"), ""); // anonymous traffic
  const plain = new URLSearchParams(analyticsQuery({ range: "nope", apiId: null, consumer: null }, NOW));
  assert.equal(plain.get("start"), "2026-11-01T11:00:00.000Z"); // unknown range: last hour
  assert.equal(plain.has("api_id") || plain.has("consumer"), false);
  assert.ok(RANGES.every((r) => r.seconds <= 31 * 86400)); // the server accepts at most 31 days
});

test("formatting", () => {
  assert.equal(fmtMs(null), "-");
  assert.equal(fmtMs(3.25), "3.3 ms");
  assert.equal(fmtMs(250.4), "250 ms");
  assert.equal(fmtMs(1500), "1.50 s");
  assert.equal(fmtPct(0.5), "50.0%");
  assert.equal(fmtPct(0.0004), "0.04%");
  assert.equal(fmtBytes(512), "512 B");
  assert.equal(fmtBytes(1536), "1.5 KB");
  assert.equal(consumerLabel(""), "(anonymous)");
  assert.equal(statusClass(503), "bad");
  assert.equal(statusClass(404), "warn");
  assert.equal(statusClass(200), "");
});

function point(t: number, requests: number, errors: number, p95: number | null): AnalyticsPoint {
  return { t, requests, errors, error_rate: 0, latency_p50_ms: p95, latency_p95_ms: p95, latency_p99_ms: p95 };
}

test("chart bars are placed by time slot and scaled to the busiest slot", () => {
  const bars = trafficBars([point(0, 10, 5, 20), point(540, 5, 0, null)], 0, 600, 60, 100, 50);
  assert.equal(bars.length, 2);
  assert.equal(bars[0].x, 0);
  assert.equal(bars[0].height, 50);
  assert.equal(bars[0].errorHeight, 25);
  assert.equal(bars[1].x, 90);
  assert.equal(bars[1].height, 25);
  const line = latencyLine([point(0, 1, 0, 20), point(60, 1, 0, null), point(120, 1, 0, 10)], 0, 600, 60, 100, 50, 20);
  assert.equal(line, "4.0,0.0 24.0,25.0");
});
