# ADR-003 — Local-first processing

**Status:** accepted · **Date:** 2026-08-08

## Context

The tool inspects credential metadata, agent configuration and cloud identity on
a developer's machine. Trust is the adoption constraint: a security tool that
exfiltrates by default will not be run.

## Decision

Everything works offline. Discovery, scanning, policy evaluation, explanation and
local enforcement require no account and no network.

- Telemetry **off** by default.
- Cloud sync explicit, never implicit, with `--dry-run` showing exactly what
  would leave the machine.
- Secret **values** never leave the process, and never enter logs or evidence.

## Consequences

- The local policy engine cannot depend on a remote PDP. Network loss must not
  affect purely local policies.
- Evidence is stored locally with restrictive permissions.
- Enterprise correlation is genuinely additive rather than a gate on basic use.
