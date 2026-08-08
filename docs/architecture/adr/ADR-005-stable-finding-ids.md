# ADR-005 — Stable UVR finding IDs

**Status:** accepted · **Date:** 2026-08-08

## Context

Findings are suppressed, tracked in tickets, gated on in CI, and cited in
audits. Category strings (`secret_leak`, `typosquat`) are not stable enough for
that: they describe a class, not a specific check, and they change meaning as
detectors improve.

The platform's 30 existing detection rules have their own identifiers and no
`UVR-` registry.

## Decision

Every detector maps to one stable `UVR-XXXX` ID, recorded in
`docs/findings/catalog.yaml`.

- One ID means exactly one semantic issue.
- **IDs are never recycled.** A retired check keeps its ID, marked `deprecated`.
- Broadening a detector's meaning requires a new ID, not an edit.

## Consequences

- The mapping from existing rules must be defined once, now. Doing it after both
  codebases ship more rules is materially harder.
- Suppression entries reference an ID and cannot silently change target.
- SARIF `ruleId` is the same ID, so GitHub code scanning stays stable across
  releases.
