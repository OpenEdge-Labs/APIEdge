// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { ApiError, api, describeDetail, readCookie, setFetcher, setSessionEndedHandler } from "../src/api";

type Call = { url: string; init: RequestInit };

function respond(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function script(...responses: Response[]): Call[] {
  const calls: Call[] = [];
  setFetcher(async (url, init) => {
    calls.push({ url, init });
    const next = responses.shift();
    if (!next) throw new Error(`unexpected request ${url}`);
    return next;
  });
  return calls;
}

function header(c: Call, name: string): string | undefined {
  return (c.init.headers as Record<string, string>)[name];
}

(globalThis as { document?: { cookie: string } }).document = { cookie: "x=1; apiedge_csrf=tok%3D1" };

test("readCookie parses and decodes", () => {
  assert.equal(readCookie("apiedge_csrf", "a=b; apiedge_csrf=v%20w"), "v w");
  assert.equal(readCookie("missing", "a=b"), undefined);
});

test("unsafe requests carry the CSRF header, safe ones do not", async () => {
  const calls = script(respond(200, { ok: 1 }), respond(204));
  assert.deepEqual(await api("/tenants"), { ok: 1 });
  assert.equal(await api("/tenants/1", { method: "DELETE" }), undefined);
  assert.equal(header(calls[0], "X-CSRF-Token"), undefined);
  assert.equal(header(calls[1], "X-CSRF-Token"), "tok=1");
  assert.equal(calls[1].url, "/api/v1/tenants/1");
  assert.equal(calls[1].init.credentials, "same-origin");
});

test("a 401 renews the session once and retries", async () => {
  const calls = script(respond(401, { detail: "invalid_token" }), respond(200, {}), respond(200, { id: 3 }));
  assert.deepEqual(await api("/auth/me"), { id: 3 });
  assert.deepEqual(calls.map((c) => c.url), ["/api/v1/auth/me", "/api/v1/auth/refresh", "/api/v1/auth/me"]);
  assert.equal(header(calls[1], "X-CSRF-Token"), "tok=1");
});

test("a failed renewal ends the session", async () => {
  let ended = 0;
  setSessionEndedHandler(() => {
    ended += 1;
  });
  script(respond(401, { detail: "invalid_token" }), respond(401, { detail: "invalid_token" }));
  await assert.rejects(api("/auth/me"), (e: unknown) => e instanceof ApiError && e.status === 401);
  assert.equal(ended, 1);
});

test("sign-in errors are not retried and keep their code", async () => {
  const calls = script(respond(401, { detail: "mfa_required" }));
  await assert.rejects(
    api("/auth/login", { method: "POST", body: {}, noRefresh: true }),
    (e: unknown) => e instanceof ApiError && e.code === "mfa_required",
  );
  assert.equal(calls.length, 1);
});

test("error details become readable text", () => {
  assert.equal(describeDetail("permission_denied"), "You do not have permission to do that.");
  assert.equal(describeDetail({ password: ["too short", "too common"] }), "password: too short, too common");
  assert.equal(describeDetail([{ loc: ["body", "slug"], msg: "bad slug" }]), "slug: bad slug");
  assert.equal(new ApiError(500, undefined).message, "HTTP 500");
});
