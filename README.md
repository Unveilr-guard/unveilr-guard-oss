<!--
SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Unveilr Guard

**See what your AI coding agents can access — and stop dangerous supported
actions before execution.**

Discover what your agents can reach. Understand their blast radius. Block
dangerous supported actions before they run.

```console
$ unveilr scan                  # what agents and MCP servers exist on this machine
$ unveilr .                     # what AI-SDLC risk is in this repository
$ unveilr proxy --server <id> -- <command>   # shield a local MCP server
```

Open source, AGPL-3.0-only. Works entirely offline — no account, no telemetry,
nothing leaves your machine unless you ask it to.

---

## Why this exists

AI coding agents run with your credentials. A single agent on a developer laptop
typically has: a cloud identity that can assume other roles, MCP servers rooted
above the project directory, a shell, and long-lived keys sitting in `~/.aws`.

Most teams cannot answer three questions about that:

- **how many agents do we have?**
- **what can they reach?**
- **who owns them?**

Unveilr Guard answers those from the machine the agents run on, explains why a
path is dangerous, and — where it sits authoritatively in the call path — refuses
the action.

## Status

**Pre-1.0.** Schemas are versioned `v1alpha1` and may change before 1.0; breaking
changes are documented. See [ROADMAP.md](ROADMAP.md).

## Install

```bash
# build from source
go install go.unveilr.ai/guard/cmd/unveilr@latest
```

## What it does

### Discover (`unveilr scan`)

Fingerprints locally-installed coding agents (Claude Code, Claude Desktop,
Cursor, GitHub Copilot — presence evidence only) and finds locally-configured
MCP servers across those same clients plus project `.mcp.json`.

**Credential values are never read, printed, logged or stored.** Any
credential-shaped value in a server's arguments or URL is replaced with
`[REDACTED]` before it leaves the process — the flag or parameter name
survives ("this server holds an API key" is the useful signal), only the
value is stripped.

### Inspect (`unveilr <path>`)

Runs detectors over a repository and reports findings — secrets, prompt
injection, command/SQL injection, path traversal, PII — with a stable rule ID,
severity, and the message that explains it. The bare, unqualified invocation:
this is the product's headline capability, not one action among several, and
`scan` was already the name for agent/MCP-server discovery above.

```console
$ unveilr . --fail-on high
1 finding(s) across 12 file(s) scanned under . (risk score 40/100):

  CRITICAL SEC-AWS  AWS access key id
           handler.py
```

`--json` for machine output, `--fail-on <severity>` to gate CI on it (exit
non-zero at or above the threshold; default `critical`).

[docs/findings/catalog.yaml](docs/findings/catalog.yaml) documents 29 rules
under `UVR-XXXX` IDs — that catalogue is the target shape, not the shipped
one: the detector currently implements 11 rules under a different scheme
entirely (`SEC-AWS`, `PI-001`, `CI-002`, …, see
[internal/scanner/detect/detect.go](internal/scanner/detect/detect.go)).
Neither the ID format nor the coverage match yet.

### Guard

A local MCP gateway that evaluates each tool call against your policy before
forwarding it upstream.

```
Agent ──MCP──▶ Unveilr Guard ──▶ policy ──▶ allow ──▶ upstream server
                              └──▶ deny  ──▶ controlled error + evidence
```

Policies are YAML, evaluated deterministically:

```yaml
apiVersion: guard.unveilr.ai/v1alpha1
kind: Policy
metadata:
  name: protect-production
spec:
  rules:
    - id: protect-iam
      description: Agents may not perform dangerous IAM changes.
      match:
        action.provider: aws
        action.name: [iam:PassRole, iam:AttachRolePolicy, iam:PutRolePolicy]
      effect: deny
```

## Limitations

Read this section. It is the part most tools leave out.

- **Runtime enforcement is adapter-specific.** Unveilr Guard blocks actions on
  paths where it sits authoritatively — today, the MCP gateway. It does not
  intercept everything an agent does, and it never claims to.
- **A local guard can be bypassed** by any process that does not route through
  its interception path.
- **Discovery is not proof of exploitability.** Finding that an agent *can* reach
  something is not evidence that it has, or that an attacker could.
- **Credential discovery does not imply exfiltration.** We detect that a
  credential is reachable, nothing more.
- **Privilege analysis may be incomplete.** Where conditional IAM cannot be fully
  resolved, findings say so and carry a lower confidence.
- **This is not a replacement** for CSPM, EDR, IAM, SIEM or sandboxing. It
  answers a narrower question: what can this agent do, and should it.
- **Organisation-wide correlation requires the commercial control plane.** A
  single workstation cannot see the organisation, and this tool will not pretend
  otherwise.

## Open source vs Enterprise

The open-source product is not a demo, a trial, or an installer for something
else. It is designed to be genuinely useful with no account.

| | Unveilr Guard (this repo, AGPL) | Unveilr Guard Enterprise |
|---|---|---|
| Discover · inventory · assess · explain | ✓ | ✓ |
| Policy-as-code, local evaluation | ✓ | ✓ |
| Local enforcement (supported adapters) | ✓ | ✓ |
| Local evidence | ✓ | ✓ |
| Organisation-wide identity graph | — | ✓ |
| Cross-workstation / cross-account correlation | — | ✓ |
| Central decisioning, approvals, step-up | — | ✓ |
| Distributed enforcement, containment | — | ✓ |
| Tamper-evident central evidence, retention | — | ✓ |

Enterprise is reached over **HTTPS**. The AGPL binary never links proprietary
code — see [ADR-002](docs/architecture/adr/ADR-002-agpl-and-network-boundary.md)
and [ADR-007](docs/architecture/adr/ADR-007-no-proprietary-imports.md).

**We do not remove capability from the OSS product to create Enterprise value.**
The split is organisational scope, not artificial crippling.

## Privacy

- Everything works offline.
- **Telemetry is off by default** (`telemetry.enabled: false`).
- Cloud sync is explicit; `unveilr cloud sync --dry-run` shows exactly what would
  be uploaded and what never will be.
- Secret values, source code, prompts, environment variable values and file
  contents are never uploaded.

See [docs/privacy.md](docs/privacy.md).

## Contributing

New detection rules are especially welcome, and there is a bar: a rule needs a
threat, preconditions, evidence, severity and confidence rationale, likely false
positives, remediation, and a test fixture. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please do not open public issues for vulnerabilities. Use GitHub Private
Vulnerability Reporting — see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0-only](LICENSE). The AGPL **permits commercial use**; this is not a
non-commercial licence. If you need to embed or redistribute Unveilr Guard inside
a proprietary product, see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

"Unveilr" and "Unveilr Guard" are trademarks — see [TRADEMARKS.md](TRADEMARKS.md).
The licence covers the software, not the marks.

> Licensing, plugin, embedding, combined-work, trademark, CLA, and commercial
> licensing terms should be reviewed by qualified legal counsel before public
> release.
