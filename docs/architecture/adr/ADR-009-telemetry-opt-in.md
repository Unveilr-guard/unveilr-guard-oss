# ADR-009 — Telemetry is opt-in

**Status:** accepted · **Date:** 2026-08-08

## Context

The tool runs where secrets, source code and prompts are. Default-on telemetry
would be disqualifying for the buyer this is aimed at.

## Decision

`telemetry.enabled: false` by default. Enabling is an explicit command.

If enabled, only privacy-preserving operational data: CLI version, command
category, anonymous install ID, OS, success/failure, timing.

Never collected: prompts, code, file paths, secrets, environment values, command
arguments, or resource identifiers.

## Consequences

- Adoption metrics are weaker. Accepted deliberately.
- Any new telemetry field is a reviewable change against this ADR, not a
  judgement call at the call site.
