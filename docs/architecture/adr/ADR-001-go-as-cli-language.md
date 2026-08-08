# ADR-001 — Go as the CLI language

**Status:** accepted · **Date:** 2026-08-08

## Context

Unveilr Guard runs on developer workstations and CI runners. It must start
instantly, ship as a single file, and be installable without a runtime.

The existing Unveilr platform CLI is Python packaged with PyInstaller. Its
artefacts are ~30 MB per platform, and it carries a real portability cost: the
published Linux binary required GLIBC 2.38 and refused to start on Debian 12 and
Ubuntu 22.04 until the build runner was moved back to an older base.

## Decision

Go, with Cobra for the command tree.

## Consequences

- Static binaries, cross-compiled from one host, no runtime on the target.
- The GLIBC class of failure disappears.
- `apps/local-shield` in the platform repo is already Go and becomes the seed.
- Detection rules are **data** (`detection-rules.json`), so they port without a
  rewrite; only the engines around them are new.
- Two CLIs exist during migration. `get.unveilr.ai` currently serves the Python
  one to a design partner; cutting over is a migration, not a build step.
