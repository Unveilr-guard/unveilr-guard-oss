# ADR-004 — ActionIntent as the normalisation point

**Status:** accepted · **Date:** 2026-08-08

## Context

Adapters observe different things: an MCP tool call, a shell command, a cloud API
call. Policy should be written once against a stable shape.

## Decision

Every adapter normalises to **ActionIntent** before evaluation, and every
evaluation returns **Decision**. Both are versioned schemas under
`guard.unveilr.ai/v1alpha1`.

`action.type` is an open vocabulary (`mcp.tool`, `shell.exec`, `cloud.api`).
Provider specifics live in `action.provider` / `action.name`. **AWS is not
hard-coded into the generic structure.**

## Consequences

- A new adapter needs a normaliser, not a policy language change.
- The same `ActionIntent` can later be sent to the enterprise PDP unchanged,
  which is the point of ADR-002's network boundary.
- Effects reserved for enterprise (`require_approval`, `step_up`, `quarantine`)
  are in the schema from day one so no redesign is needed to support them.
