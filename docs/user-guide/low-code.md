<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Low-code (status)

APIEdge's low-code tools let you add small pieces of logic where forms are not enough. This page
says plainly what exists today and what is still to come, so you can plan around it.

## Available today

There is **no scripting yet**. What you can do without code:

| Need | Use today |
|---|---|
| Add, change or remove request and response headers or query parameters | [Header / body transform](policies.md#header-body-transform) policy |
| Set or remove fields (by dot path) of a JSON request or response body | [Header / body transform](policies.md#header-body-transform) policy |
| Answer with a fixed response while the backend does not exist | [Mock response](policies.md#mock-response) policy |
| Apply a policy only to some operations | the **Routes** selection on each policy |
| Automate configuration | the [Admin API](../api/index.md) from any scripting language |

## Upcoming

The following are planned and **not available yet**. Their scope is defined by the task list;
details may change when they are delivered.

| Feature | Task | What it will add |
|---|---|---|
| Visual policy flow builder | T-009 | A drag-and-drop canvas to build and reorder policy chains (requires T-008, done) |
| Script policy | T-010 | Policies and transforms written in a restricted subset of Python, run in an isolated worker process with CPU, time and memory limits and no network or file access; an in-browser editor with a test runner (requires T-009) |
| OpenAPI import and export | T-011 | Create an API and its routes from an OpenAPI document, and export an API as OpenAPI |
| Assembly policies | T-022 | Flow constructs (switch, if, throw/catch, set-variable), visual data mapping, validation, redaction, XML/JSON conversion |

This guide will document each feature when its task is delivered. The
[feature parity matrix](../FEATURE_MATRIX.md) tracks the status of every capability.
