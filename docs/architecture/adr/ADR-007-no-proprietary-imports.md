# ADR-007 — No proprietary imports, enforced by CI

**Status:** accepted · **Date:** 2026-08-08

## Context

ADR-002 sets a licence boundary. A boundary that is only a convention will be
crossed by accident.

## Decision

CI fails if the module graph contains any proprietary Unveilr path. The check
runs on every pull request, not only on release.

## Consequences

- Shared logic with the platform is duplicated deliberately or extracted to a
  separately-licensed module — never imported across the boundary.
- Wire compatibility is maintained through **schemas**, which are the contract,
  rather than through shared code.
