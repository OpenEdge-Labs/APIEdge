// Copyright 2026 Alingan Patra
// SPDX-License-Identifier: Apache-2.0
// Console unit tests without extra dependencies: compile the tests (and the modules they import)
// with the project's TypeScript, then run them with Node's built-in test runner.
import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const out = ".test-build";
rmSync(out, { recursive: true, force: true });
const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
const run = (args) => spawnSync(process.execPath, args, { stdio: "inherit" }).status ?? 1;

if (run([tsc, "-p", "tsconfig.test.json"]) !== 0) process.exit(1);
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "package.json"), '{ "type": "commonjs" }\n');
const tests = readdirSync(join(out, "test"))
  .filter((f) => f.endsWith(".test.js"))
  .map((f) => join(out, "test", f));
process.exit(run(["--test", ...tests]));
