// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package schema

// Effect is the outcome of evaluating an ActionIntent.
//
// The vocabulary is deliberately the FULL enterprise set, not just the three
// the local engine implements. A local decision and a centrally-returned
// decision then share one schema, and supporting approvals later needs no
// redesign (ADR-004). This ordering mirrors the Unveilr enterprise policy engine
// exactly; a test asserts the sequence has not drifted.
type Effect string

const (
	EffectAllow           Effect = "allow"
	EffectRedact          Effect = "redact"
	EffectSanitize        Effect = "sanitize"
	EffectScopedToken     Effect = "scoped_token"
	EffectRequireApproval Effect = "require_approval"
	EffectStepUp          Effect = "step_up"
	EffectDeny            Effect = "deny"
)

// EffectWarn allows the action but records it. Local-only, and deliberately
// absent from Precedence: it does not change what happens, so ordering it
// against effects that do would imply a restriction it never applies.
const EffectWarn Effect = "warn"

// Precedence is ordered by increasing restriction.
//
// Combination is forbid-overrides: the most restrictive matching effect wins.
// The property that matters is that ADDING a policy can never widen access —
// so an operator can add a rule without auditing every existing one.
var Precedence = []Effect{
	EffectAllow,
	EffectRedact,
	EffectSanitize,
	EffectScopedToken,
	EffectRequireApproval,
	EffectStepUp,
	EffectDeny,
}

// rank returns the restriction rank of an effect, and whether it is known.
func rank(e Effect) (int, bool) {
	for i, p := range Precedence {
		if p == e {
			return i, true
		}
	}
	return 0, false
}

// MoreRestrictive returns whichever of a and b is more restrictive.
//
// An unknown effect is treated as the MOST restrictive rather than ignored:
// failing closed on something we do not understand is the only safe reading, and
// silently skipping it would let a typo in a policy widen access.
func MoreRestrictive(a, b Effect) Effect {
	ra, aok := rank(a)
	rb, bok := rank(b)
	switch {
	case !aok:
		return a
	case !bok:
		return b
	case ra >= rb:
		return a
	default:
		return b
	}
}

// LocallySupported reports whether this build can carry out an effect.
//
// The others need capability the local guard does not have: an approval surface,
// a credential broker, a step-up channel. The caller MUST NOT treat an
// unsupported effect as an allow — see Decision.SupportedLocally.
func LocallySupported(e Effect) bool {
	switch e {
	case EffectAllow, EffectDeny, EffectWarn:
		return true
	default:
		return false
	}
}

// Decision is the outcome of evaluating an ActionIntent against a policy set.
type Decision struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	IntentID   string `json:"intentId"`
	Timestamp  string `json:"timestamp"`

	Effect Effect `json:"effect"`
	// SupportedLocally is false when Effect needs capability this build lacks.
	SupportedLocally bool `json:"supportedLocally"`

	// Reason is for the human reading a denial at 03:00.
	Reason string `json:"reason,omitempty"`
	// ReasonCodes are for rules and dashboards. Emitted ALONGSIDE Reason, never
	// instead of it, in first-occurrence order: the first code is the gate that
	// fired first, which is the one to act on.
	ReasonCodes []string `json:"reasonCodes,omitempty"`

	MatchedPolicy string `json:"matchedPolicy,omitempty"`
	MatchedRule   string `json:"matchedRule,omitempty"`

	Engine      Engine         `json:"engine"`
	Constraints map[string]any `json:"constraints,omitempty"`
}

// Engine identifies what produced a decision, and pins the policy set.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// PolicySetHash makes a decision reproducible. Without it a decision cannot
	// be replayed, and a decision that cannot be replayed cannot be evidence.
	PolicySetHash string `json:"policySetHash,omitempty"`
}

// Reason codes. A closed set: a code emitted anywhere must be listed here, so a
// typo fails the build rather than shipping a code nobody can match on.
const (
	CodePolicyDeny        = "POLICY_DENY"
	CodePolicyWarn        = "POLICY_WARN"
	CodeNoPolicyMatched   = "NO_POLICY_MATCHED"
	CodeEffectUnsupported = "EFFECT_UNSUPPORTED_LOCALLY"
	CodeNoPoliciesLoaded  = "NO_POLICIES_LOADED"
)
