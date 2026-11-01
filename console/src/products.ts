// Copyright 2026 OpenEdge Labs
// SPDX-License-Identifier: Apache-2.0
// Product rules shared by the console screens (T-005). The server enforces them on its own.
import type { Lifecycle } from "./types";

/** Lifecycle moves the server accepts (draft -> published -> deprecated -> retired). */
export const TRANSITIONS: Record<Lifecycle, Lifecycle[]> = {
  draft: ["published", "retired"],
  published: ["deprecated"],
  deprecated: ["published", "retired"],
  retired: [],
};

/** Only draft and retired products can be deleted. */
export function deletable(lifecycle: Lifecycle): boolean {
  return lifecycle === "draft" || lifecycle === "retired";
}

/** Splits "a, b  c" into unique usernames. */
export function parseOwners(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))];
}
