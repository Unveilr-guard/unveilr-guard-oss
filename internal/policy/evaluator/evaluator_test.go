// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package evaluator_test

import (
	"context"
	"testing"
	"time"

	"go.unveilr.ai/guard/internal/policy/evaluator"
	"go.unveilr.ai/guard/pkg/policy"
	"go.unveilr.ai/guard/pkg/schema"
)

func newEval() *evaluator.Local {
	e := evaluator.New("test")
	e.Now = func() time.Time { return time.Unix(0, 0).UTC() }
	return e
}

func rule(id string, effect schema.Effect, match map[string][]string) policy.Rule {
	m := map[string]policy.Matcher{}
	for k, v := range match {
		m[k] = policy.Matcher{Values: v}
	}
	return policy.Rule{ID: id, Match: m, Effect: effect}
}

func pol(name string, rules ...policy.Rule) policy.Policy {
	return policy.Policy{
		APIVersion: schema.APIVersion,
		Kind:       schema.KindPolicy,
		Metadata:   policy.Metadata{Name: name},
		Spec:       policy.Spec{Rules: rules},
	}
}

func intent() schema.ActionIntent {
	return schema.ActionIntent{
		APIVersion: schema.APIVersion,
		Kind:       schema.KindActionIntent,
		ID:         "int_1",
		Agent:      schema.Agent{ID: "agent_a", Type: "coding-assistant"},
		Actor:      &schema.Actor{Type: schema.ActorUnattended},
		Action:     schema.Action{Type: schema.ActionCloudAPI, Provider: "aws", Name: "iam:PassRole"},
		Resource:   &schema.Resource{Type: "aws.iam.role", ID: "arn:aws:iam::1:role/admin", DataClasses: []string{"credentials"}},
	}
}

func decide(t *testing.T, in schema.ActionIntent, ps ...policy.Policy) schema.Decision {
	t.Helper()
	d, err := newEval().Evaluate(context.Background(), in, ps)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return d
}

func TestDenyRuleMatches(t *testing.T) {
	t.Parallel()

	d := decide(t, intent(), pol("baseline", rule("no-passrole", schema.EffectDeny,
		map[string][]string{"action.name": {"iam:PassRole"}})))

	if d.Effect != schema.EffectDeny {
		t.Fatalf("effect = %q, want deny", d.Effect)
	}
	if d.MatchedRule != "no-passrole" || d.MatchedPolicy != "baseline" {
		t.Errorf("decision must name what produced it, got %q/%q", d.MatchedPolicy, d.MatchedRule)
	}
	if !hasCode(d, schema.CodePolicyDeny) {
		t.Errorf("reason codes = %v", d.ReasonCodes)
	}
	if d.Reason == "" {
		t.Error("a denial with no prose is unreadable at 03:00")
	}
	if d.Engine.PolicySetHash == "" {
		t.Error("decision without a policy set hash cannot be replayed, so it cannot be evidence")
	}
}

func TestAllConstraintsInARuleMustMatch(t *testing.T) {
	t.Parallel()

	// A rule constraining action AND agent must not fire on the action alone.
	r := rule("narrow", schema.EffectDeny, map[string][]string{
		"action.name": {"iam:PassRole"},
		"agent.id":    {"some-other-agent"},
	})
	d := decide(t, intent(), pol("baseline", r))

	if d.Effect != schema.EffectAllow {
		t.Fatalf("effect = %q, want allow: only one of two constraints matched", d.Effect)
	}
	if !hasCode(d, schema.CodeNoPolicyMatched) {
		t.Errorf("reason codes = %v", d.ReasonCodes)
	}
}

func TestAbsentFieldDoesNotMatchEmptyString(t *testing.T) {
	t.Parallel()

	// "Absence is not clean": an intent that never declared a field must not
	// match a rule looking for a specific value there, and must not match "".
	in := intent()
	in.Resource = nil

	d := decide(t, in, pol("baseline", rule("classes", schema.EffectDeny,
		map[string][]string{"resource.dataClasses": {"credentials"}})))

	if d.Effect != schema.EffectAllow {
		t.Fatalf("effect = %q: a missing resource matched a rule about its contents", d.Effect)
	}
}

func TestMultiValuedFieldMatchesOnAnyValue(t *testing.T) {
	t.Parallel()

	in := intent()
	in.Resource.DataClasses = []string{"public", "credentials"}

	d := decide(t, in, pol("baseline", rule("secrets", schema.EffectDeny,
		map[string][]string{"resource.dataClasses": {"credentials"}})))

	if d.Effect != schema.EffectDeny {
		t.Fatalf("effect = %q: a resource carrying credentials alongside other classes must still match", d.Effect)
	}
}

func TestMostRestrictiveMatchWins(t *testing.T) {
	t.Parallel()

	// Forbid-overrides across policies: an allow rule cannot rescue an action a
	// deny rule caught, whatever order the policies load in.
	allow := pol("a-permissive", rule("allow-all-aws", schema.EffectAllow,
		map[string][]string{"action.provider": {"aws"}}))
	deny := pol("z-restrictive", rule("no-passrole", schema.EffectDeny,
		map[string][]string{"action.name": {"iam:PassRole"}}))

	forward := decide(t, intent(), allow, deny)
	reverse := decide(t, intent(), deny, allow)

	if forward.Effect != schema.EffectDeny || reverse.Effect != schema.EffectDeny {
		t.Fatalf("effects = %q and %q, want deny both ways", forward.Effect, reverse.Effect)
	}
	if forward.MatchedRule != reverse.MatchedRule {
		t.Errorf("winning rule depends on load order: %q vs %q", forward.MatchedRule, reverse.MatchedRule)
	}
}

func TestUnsupportedEffectIsReportedNotDowngraded(t *testing.T) {
	t.Parallel()

	// SG-07: the caller must be able to tell "policy says require approval and I
	// cannot do that here" from "allowed". Silently treating it as allow would
	// make the guard report enforcement that never happened.
	d := decide(t, intent(), pol("baseline", rule("approve", schema.EffectRequireApproval,
		map[string][]string{"action.name": {"iam:PassRole"}})))

	if d.Effect != schema.EffectRequireApproval {
		t.Fatalf("effect = %q, want the policy's effect preserved", d.Effect)
	}
	if d.SupportedLocally {
		t.Error("require_approval reported as locally supported")
	}
	if !hasCode(d, schema.CodeEffectUnsupported) {
		t.Errorf("reason codes = %v", d.ReasonCodes)
	}
}

func TestNoPoliciesIsDistinguishableFromNothingMatched(t *testing.T) {
	t.Parallel()

	// Both allow, but for very different reasons: one is usually a broken
	// configuration, and an operator must be able to tell them apart from the
	// decision alone.
	empty := decide(t, intent())
	unmatched := decide(t, intent(), pol("baseline", rule("other", schema.EffectDeny,
		map[string][]string{"action.name": {"s3:DeleteBucket"}})))

	if !hasCode(empty, schema.CodeNoPoliciesLoaded) {
		t.Errorf("no policies: reason codes = %v", empty.ReasonCodes)
	}
	if !hasCode(unmatched, schema.CodeNoPolicyMatched) {
		t.Errorf("nothing matched: reason codes = %v", unmatched.ReasonCodes)
	}
	if hasCode(empty, schema.CodeNoPolicyMatched) {
		t.Error("an empty policy set must not report NO_POLICY_MATCHED")
	}
}

func TestDefaultEffectIsConfigurable(t *testing.T) {
	t.Parallel()

	e := newEval()
	e.Default = schema.EffectDeny
	d, err := e.Evaluate(context.Background(), intent(), []policy.Policy{
		pol("baseline", rule("other", schema.EffectDeny, map[string][]string{"action.name": {"s3:Get"}})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != schema.EffectDeny {
		t.Fatalf("effect = %q: deny-by-default was configured and ignored", d.Effect)
	}
}

func TestContextPathsResolve(t *testing.T) {
	t.Parallel()

	in := intent()
	in.Context = map[string]any{"environment": "production", "sessionDepth": 3}

	d := decide(t, in, pol("baseline", rule("prod", schema.EffectDeny,
		map[string][]string{"context.environment": {"production"}})))
	if d.Effect != schema.EffectDeny {
		t.Fatalf("effect = %q: context.environment did not resolve", d.Effect)
	}

	// Non-string context values must be comparable too, or a policy about
	// numeric context silently never fires.
	d = decide(t, in, pol("baseline", rule("depth", schema.EffectDeny,
		map[string][]string{"context.sessionDepth": {"3"}})))
	if d.Effect != schema.EffectDeny {
		t.Fatalf("effect = %q: a numeric context value did not resolve", d.Effect)
	}

	// An absent context key must not match.
	d = decide(t, in, pol("baseline", rule("absent", schema.EffectDeny,
		map[string][]string{"context.nothing": {"x"}})))
	if d.Effect != schema.EffectAllow {
		t.Fatalf("effect = %q: an absent context key matched", d.Effect)
	}
}

func TestEvaluationIsDeterministic(t *testing.T) {
	t.Parallel()

	// Same intent, same policies, same decision — including which rule is cited
	// when two equally restrictive rules match. Go map iteration is randomised,
	// so this is a real risk, not a theoretical one.
	ps := []policy.Policy{
		pol("baseline",
			rule("b-rule", schema.EffectDeny, map[string][]string{"action.provider": {"aws"}}),
			rule("a-rule", schema.EffectDeny, map[string][]string{"action.name": {"iam:PassRole"}}),
		),
		pol("extra", rule("c-rule", schema.EffectDeny, map[string][]string{"agent.id": {"agent_a"}})),
	}

	first := decide(t, intent(), ps...)
	for i := 0; i < 50; i++ {
		got := decide(t, intent(), ps...)
		if got.MatchedRule != first.MatchedRule || got.Effect != first.Effect {
			t.Fatalf("run %d differed: %q/%q vs %q/%q", i, got.MatchedPolicy, got.MatchedRule, first.MatchedPolicy, first.MatchedRule)
		}
		if got.Engine.PolicySetHash != first.Engine.PolicySetHash {
			t.Fatalf("run %d: policy set hash changed", i)
		}
	}
}

func TestHandBuiltRuleWithNoMatchNeverFires(t *testing.T) {
	t.Parallel()

	// Validation rejects this, but a Rule constructed in code bypasses validation.
	// A rule matching everything must not be the failure mode.
	d := decide(t, intent(), pol("baseline", policy.Rule{ID: "empty", Effect: schema.EffectDeny}))
	if d.Effect != schema.EffectAllow {
		t.Fatalf("effect = %q: a rule with no constraints applied to everything", d.Effect)
	}
}

func hasCode(d schema.Decision, code string) bool {
	for _, c := range d.ReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}
