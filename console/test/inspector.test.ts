// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_FILTERS,
  bodyText,
  captureBody,
  captureErrors,
  exchangeQuery,
  mergeExchanges,
  parseMaskFields,
  prettyJson,
  remaining,
  type CaptureForm,
} from "../src/inspector";
import type { CaptureSession, ExchangeSummary } from "../src/types";

const ex = (id: number): ExchangeSummary => ({
  id,
  session_id: 1,
  product_id: 1,
  api_id: 1,
  request_id: `r${id}`,
  started_at: "2026-11-02T10:00:00Z",
  method: "GET",
  path: "/acme/x",
  route: "/*",
  status: 200,
  consumer: "",
  duration_ms: 1,
  upstream: "",
});

test("the filter query carries only the filters that are set", () => {
  assert.equal(exchangeQuery(EMPTY_FILTERS), "");
  const q = new URLSearchParams(
    exchangeQuery({ sessionId: 3, method: " post", statusClass: 5, path: "/a b", consumer: "key:m" }, { limit: 50 }),
  );
  assert.equal(q.get("session_id"), "3");
  assert.equal(q.get("method"), "POST");
  assert.equal(q.get("status_class"), "5");
  assert.equal(q.get("path"), "/a b");
  assert.equal(q.get("consumer"), "key:m");
  assert.equal(q.get("limit"), "50");
});

test("live rows merge newest first without duplicates and stay bounded", () => {
  const merged = mergeExchanges([ex(2), ex(1)], [ex(3), ex(2)], 2);
  assert.deepEqual(
    merged.map((e) => e.id),
    [3, 2],
  );
});

test("bodies are shown readably", () => {
  assert.ok(/not captured/.test(bodyText({ captured: false, size: 0, truncated: false, encoding: "utf-8", text: "" })));
  assert.equal(bodyText({ captured: true, size: 0, truncated: false, encoding: "utf-8", text: "" }), "(empty)");
  assert.equal(bodyText({ captured: true, size: 7, truncated: false, encoding: "utf-8", text: '{"a":1}' }), '{\n  "a": 1\n}');
  assert.ok(/99 bytes in total/.test(bodyText({ captured: true, size: 99, truncated: true, encoding: "utf-8", text: "abc" })));
  assert.ok(/binary/.test(bodyText({ captured: true, size: 2, truncated: false, encoding: "base64", text: "AAA=" })));
  assert.equal(prettyJson("{broken"), "{broken");
});

test("remaining time of a capture", () => {
  const s = { state: "active", expires_at: "2026-11-02T10:05:05Z" } as CaptureSession;
  assert.equal(remaining(s, new Date("2026-11-02T10:00:00Z")), "5m 05s left");
  assert.equal(remaining({ ...s, state: "stopped" }, new Date()), "stopped");
});

test("capture form validation and body", () => {
  const form: CaptureForm = {
    productId: 1,
    apiId: 2,
    route: "",
    consumer: " ",
    duration: "15",
    maxExchanges: "200",
    maxBody: "16384",
    maskFields: "ssn, card.number ssn",
  };
  assert.deepEqual(captureErrors(form), []);
  assert.deepEqual(parseMaskFields(form.maskFields), ["ssn", "card.number"]);
  assert.deepEqual(captureBody(form), {
    api_id: 2,
    route: null,
    consumer: null,
    duration_minutes: 15,
    max_exchanges: 200,
    max_body_bytes: 16384,
    mask_fields: ["ssn", "card.number"],
  });
  const bad = captureErrors({ ...form, apiId: null, duration: "0", maxBody: "x", maskFields: "a b$" });
  assert.equal(bad.length, 4);
});
