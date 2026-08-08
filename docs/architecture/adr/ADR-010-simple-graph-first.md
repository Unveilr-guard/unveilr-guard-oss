# ADR-010 — A simple in-memory graph before any graph database

**Status:** accepted · **Date:** 2026-08-08

## Context

The inventory is a graph: humans, identities, agents, credentials, MCP servers,
tools, resources. The instinct is to reach for a graph database.

The platform already renders an identity graph **from relational queries** with
no graph store, and it has been sufficient.

## Decision

Serializable node/edge structures in memory for v0.1. No database, no graph
engine. Local state is files: JSON, YAML, and SQLite only if a concrete need
appears.

## Consequences

- A workstation inventory is small; traversal cost is irrelevant at this size.
- Zero operational dependency for a tool that must run anywhere.
- Organisation-wide graph reasoning is explicitly **enterprise** — a single
  workstation cannot see it, and OSS must not claim organisation-wide blast
  radius (see ADR-002).
