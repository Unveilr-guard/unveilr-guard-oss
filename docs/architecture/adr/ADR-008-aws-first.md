# ADR-008 — AWS first for cloud reasoning

**Status:** accepted · **Date:** 2026-08-08

## Context

Agent-accessible cloud privilege is where blast radius becomes concrete. Covering
every provider at once produces shallow coverage everywhere.

## Decision

AWS first, focused on capabilities that enable privilege escalation, production
mutation, credential retrieval, control bypass and logging impairment:
STS, IAM, Secrets Manager, SSM, EC2, Lambda, CloudFormation, S3, CloudTrail.

## Consequences

- This is **not CSPM**. The question is what an *agent-accessible identity* can
  do, not whether the account is well configured. No competition with Wiz,
  Prowler or Security Hub.
- Privilege analysis is incomplete where conditional IAM cannot be fully
  resolved. Findings must carry confidence and state the assumption.
- Interfaces take synthetic policy documents so tests never need an AWS account.
