// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vite";

// The console is built into the Python package so end users never need Node.js.
export default defineConfig({
  base: "/",
  esbuild: { jsx: "automatic" },
  build: {
    outDir: "../src/apiedge/static",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    // During development, forward API calls to a locally running `apiedge run`.
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/healthz": "http://127.0.0.1:8080",
      "/readyz": "http://127.0.0.1:8080",
    },
  },
});
