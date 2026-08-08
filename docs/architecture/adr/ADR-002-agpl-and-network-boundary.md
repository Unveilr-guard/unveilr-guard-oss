# ADR-002 — AGPL OSS with a network boundary to proprietary code

**Status:** accepted · **Date:** 2026-08-08

## Context

Open-core with a strong OSS product and a proprietary enterprise control plane.
The OSS product must be genuinely useful with no commercial account.

## Decision

- OSS licensed **AGPL-3.0-only**, official unmodified text.
- The AGPL executable **never imports proprietary Unveilr code**.
- Enterprise integration crosses a **network boundary** (HTTPS), never a linker.
- Contributions under a CLA so dual licensing stays possible.

```
Unveilr Guard (AGPL)  ──HTTPS──▶  Unveilr Enterprise API (proprietary)
```

## Consequences

- No in-process closed-source plugin system in v0.1; that needs explicit
  architecture and legal review.
- `CloudClient` is an interface with a configurable endpoint. The OSS repo
  contains the client and the wire schemas, never the server.
- CI must assert the absence of proprietary imports; a human rule is not enough.
- The AGPL permits commercial use. Documentation must never describe the project
  as "free for non-commercial use".
