// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// Minimal typings for the Node built-ins the console unit tests use (avoids a @types/node dependency).
declare module "node:test" {
  export function test(name: string, fn: () => void | Promise<void>): void;
}
declare module "node:assert/strict" {
  interface Assert {
    equal(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
    rejects(fn: Promise<unknown> | (() => Promise<unknown>), expected?: unknown): Promise<void>;
  }
  const assert: Assert;
  export default assert;
}
