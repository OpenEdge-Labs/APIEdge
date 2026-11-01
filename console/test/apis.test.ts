// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { basePathError, emptyForm, formErrors, formFromApi, routeKey, routePathError, toBody } from "../src/apis";
import type { Api } from "../src/types";

test("base paths follow the server rules", () => {
  assert.equal(basePathError("/orders/v1"), null);
  for (const bad of ["", "/", "orders", "/a b", "/a/../b", "/api/v1", "/api/v1/x", "/HEALTHZ"]) {
    assert.notEqual(basePathError(bad), null, bad);
  }
  assert.equal(basePathError("/api"), null);
});

test("route paths allow parameters and a final wildcard", () => {
  for (const ok of ["/", "/*", "/orders", "/orders/{id}", "/orders/{id}/items/*"]) {
    assert.equal(routePathError(ok), null, ok);
  }
  for (const bad of ["orders", "/a/*/b", "/{id}/{id}", "/a/..", "/{1x}"]) {
    assert.notEqual(routePathError(bad), null, bad);
  }
  assert.equal(routeKey("/a/{id}/b"), routeKey("/a/{other}/b"));
});

test("form errors catch overlaps, bad numbers and missing fields", () => {
  const f = emptyForm();
  assert.ok(formErrors(f).some((e) => e.startsWith("Name")));
  assert.ok(formErrors(f).some((e) => e.startsWith("Base path")));
  f.name = "Orders";
  f.base_path = "/orders";
  f.upstreams = [{ url: "https://backend.example.com", weight: "1" }];
  assert.deepEqual(formErrors(f), []);
  f.timeout_ms = "10";
  f.upstreams.push({ url: "ftp://x", weight: "0" });
  f.routes = [
    { methods: ["GET"], path: "/a/{id}", description: "" },
    { methods: ["GET", "PUT"], path: "/a/{x}", description: "" },
    { methods: [], path: "/b", description: "" },
  ];
  const errors = formErrors(f);
  assert.ok(errors.some((e) => e.startsWith("Timeout")));
  assert.ok(errors.some((e) => e.startsWith("Upstream 2: use")));
  assert.ok(errors.some((e) => e.startsWith("Upstream 2: weight")));
  assert.ok(errors.some((e) => e.includes("overlaps")));
  assert.ok(errors.some((e) => e.includes("at least one method")));
});

test("the body drops empty rows, trims and orders methods", () => {
  const f = emptyForm();
  Object.assign(f, { name: " Orders ", base_path: " /orders ", timeout_ms: "5000" });
  f.upstreams = [{ url: " https://b.example.com ", weight: "3" }, { url: "  ", weight: "1" }];
  f.routes = [{ methods: ["PUT", "GET"], path: "/x", description: "" }, { methods: ["GET"], path: "", description: "" }];
  assert.deepEqual(toBody(f), {
    name: "Orders",
    version: "v1",
    base_path: "/orders",
    description: "",
    timeout_ms: 5000,
    upstreams: [{ url: "https://b.example.com", weight: 3 }],
    routes: [{ methods: ["GET", "PUT"], path: "/x", description: "" }],
  });
});

test("an API round-trips through the form", () => {
  const a: Api = {
    id: 1, tenant_id: 1, product_id: 2, name: "Orders", version: "v2", base_path: "/o", description: "d",
    timeout_ms: 1000, lifecycle: "draft", upstreams: [{ url: "https://b.example.com", weight: 2 }],
    routes: [{ methods: ["GET"], path: "/*", description: "" }], created_at: "", updated_at: "",
  };
  const body = toBody(formFromApi(a));
  assert.equal(body.base_path, "/o");
  assert.deepEqual(body.upstreams, a.upstreams);
  assert.deepEqual(body.routes, a.routes);
});
