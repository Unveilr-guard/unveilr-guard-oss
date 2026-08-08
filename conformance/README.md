<!--
SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Cross-engine conformance

Unveilr has **three** implementations of policy effect combination:

| Engine | Language | Where | Enforces |
|---|---|---|---|
| Local guard | Go | this repository, `pkg/schema` | the developer workstation and CI |
| Policy Decision Point | Python | Unveilr enterprise, `governance/policy_eval.py` | `/v1/govern/check` |
| MCP gateway | TypeScript | Unveilr enterprise, `packages/shared/src/policy/engine.ts` | agent tool calls in-line |

"The same decision everywhere" is a product claim. Three independent
implementations make it a claim that can quietly stop being true — and a
divergence is not a cosmetic bug: it means **an action denied at one enforcement
point is permitted at another**.

`effects.json` is the shared fixture set that makes the claim falsifiable. All
three engines are tested against it.

## What is actually covered

**Covered — effect combination.** The precedence ordering, forbid-overrides
combination, commutativity, and the property that adding a policy can never
widen access. This is the part that genuinely exists identically in all three
engines, and it is the part where silent drift is most dangerous.

**Not covered — matching.** The three engines do not share a policy *language*.
The local Go engine matches dotted paths on an `ActionIntent`; the enterprise
engines match a richer selector model with conditions, scopes, and risk
thresholds. A fixture set asserting all three reach the same decision from the
same policy document would require a policy language they do not have. Claiming
otherwise would be the kind of unfalsifiable guarantee this directory exists to
prevent.

So: **combination is conformant; matching is not, and is not claimed to be.**
Closing that gap needs a shared intermediate policy representation, which is a
design decision, not a test.

## Source of truth and vendoring

`effects.json` in **this repository** is the source of truth. The enterprise repo
vendors a byte-identical copy and pins its SHA-256 in both runners:

```
2cca7dd5aeaebad4732ebdeb0802aeaaa5ee75fe40cb2125d05252afe9e181cf
```

To change the contract: edit it here, re-vendor, and update the pinned hash in
the same commit. A drifting hash with an unchanged file means someone edited a
vendored copy instead of the source — which is exactly how the contract forks.

## Running it

```bash
# Go (this repo)
go test ./pkg/schema/

# Python (enterprise)
pytest apps/api/tests/test_effect_conformance.py

# TypeScript (enterprise)
npx vitest run test/effect-conformance.test.ts --dir packages/shared
```

## Known divergence: unrecognised effects

All three engines agreed on the seven known effects. They did **not** agree on
what to do with an effect outside `precedence` — one arriving from a newer policy
bundle, a seeded row, or a typo:

| Engine | Original behaviour | Consequence |
|---|---|---|
| Go | fails closed | correct |
| Python | `.index()` raised `ValueError` | a decision request became a 500 |
| TypeScript | `indexOf` returned `-1`, ranking it below `allow` | **the effect was silently discarded in favour of the other one** |

The TypeScript case is the serious one, because that engine is the in-line
enforcement path: an unrecognised effect always lost, so a policy carrying one
would be ignored rather than respected. It was not reachable through the public
API — `POST /v1/policies` validates `effect` against a closed `Literal`, so an
unknown value cannot be written that way — which makes it a latent robustness
gap rather than a live bypass. The reachable paths are a seeded or migrated row,
a bundled policy pack, and any future effect added to one engine before the
others.

Both engines now fail closed, matching Go, and `unknownEffects` in `effects.json`
pins that behaviour. `enforcedBy` records which engines are actually asserted
against it, so the fixture never overstates its own coverage.
