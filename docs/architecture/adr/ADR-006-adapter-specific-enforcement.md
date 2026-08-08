# ADR-006 — Enforcement is adapter-specific, and says so

**Status:** accepted · **Date:** 2026-08-08

## Context

It is tempting to claim "Unveilr Guard blocks dangerous agent actions". Wrapping
a process does not give authoritative control over everything that process does.

## Decision

Each adapter declares exactly what it can and cannot intercept. The product
**never claims universal runtime enforcement**, and never reports an action as
blocked unless the adapter had authoritative control of the execution path.

`unveilr doctor` reports per-adapter capability as
`SUPPORTED · PARTIAL · NOT INSTALLED · NOT SUPPORTED · ERROR`.

## Consequences

- The **MCP gateway is the authoritative adapter** in v0.1: it is in the call
  path and can refuse before forwarding.
- Coding-agent "adapters" that cannot intercept are discovery plus status, and
  are labelled as such. Faking interception is prohibited.
- Documentation states that a local guard can be bypassed by a process outside
  its interception path. This is a limitation of the approach, not a defect to
  hide.
