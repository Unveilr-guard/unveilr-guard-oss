# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use **GitHub Private Vulnerability Reporting** on this repository
(Security → Report a vulnerability), or email `<SECURITY CONTACT>`.

## What to include

- Affected version (`unveilr version`) and platform.
- What the issue allows an attacker to do.
- Reproduction steps, or a proof of concept.
- Any suggested remediation.

**Redact secrets before sending anything.** Unveilr Guard inspects credential
*metadata*; if a report would otherwise include a real credential, replace it
with a synthetic one. We will ask you to re-send rather than accept live secrets.

## Supported versions

While the project is pre-1.0, security fixes land on the latest minor release
only. Once 1.0 ships, this section will state a support window.

| Version | Supported |
|---|---|
| `0.x` (latest minor) | yes |
| older `0.x` | no — upgrade |

## Disclosure

We aim to acknowledge reports promptly, agree a remediation timeline with you,
and credit you unless you prefer otherwise. We publish an advisory when a fix is
released.

**We do not publish a response-time SLA.** Committing to numbers we cannot
guarantee at this stage would be worse than saying so.

## Scope

In scope: the CLI, the MCP gateway, policy evaluation, redaction, discovery
parsers, and release artefacts.

Out of scope: vulnerabilities in upstream MCP servers, agent runtimes, or cloud
providers that Unveilr Guard merely observes. Report those to their maintainers —
we are glad to help you route them.
