// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package policy_test

import (
	"strings"
	"testing"

	"github.com/unveilr/unveilr-guard/pkg/policy"
	"github.com/unveilr/unveilr-guard/pkg/schema"
)

const valid = `
apiVersion: guard.unveilr.ai/v1alpha1
kind: Policy
metadata:
  name: baseline
spec:
  rules:
    - id: no-passrole
      description: iam:PassRole is privilege escalation in one call
      match:
        action.name: iam:PassRole
      effect: deny
`

func TestParseAcceptsAValidPolicy(t *testing.T) {
	t.Parallel()

	p, err := policy.Parse([]byte(valid))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Metadata.Name != "baseline" || len(p.Spec.Rules) != 1 {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if got := p.Spec.Rules[0].Match["action.name"].Values; len(got) != 1 || got[0] != "iam:PassRole" {
		t.Errorf("scalar matcher: %v", got)
	}
	if probs := policy.Validate(p); policy.Fatal(probs) {
		t.Errorf("valid policy reported fatal problems: %v", probs)
	}
}

func TestParseAcceptsScalarAndListMatchers(t *testing.T) {
	t.Parallel()

	src := strings.Replace(valid, "        action.name: iam:PassRole",
		"        action.name: [iam:PassRole, iam:CreateAccessKey]", 1)
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := p.Spec.Rules[0].Match["action.name"]
	if !m.Matches("iam:CreateAccessKey") || !m.Matches("iam:PassRole") {
		t.Errorf("list matcher did not match both values: %v", m.Values)
	}
	if m.Matches("s3:GetObject") {
		t.Error("list matcher matched a value it does not contain")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	// A misspelled key must be an error, not silence. `effct: deny` that parses
	// to nothing produces a policy that quietly never denies — the worst possible
	// failure mode for this file.
	src := strings.Replace(valid, "      effect: deny", "      effct: deny", 1)
	if _, err := policy.Parse([]byte(src)); err == nil {
		t.Fatal("expected an error for a misspelled field, got none")
	}
}

func TestValidateCatchesTheMistakesThatWouldSilentlyWeakenAPolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		mutch func(string) string
		want  string
		fatal bool
	}{
		{
			name:  "wrong apiVersion",
			mutch: func(s string) string { return strings.Replace(s, schema.APIVersion, "guard.unveilr.ai/v1", 1) },
			want:  "apiVersion",
			fatal: true,
		},
		{
			name:  "missing name",
			mutch: func(s string) string { return strings.Replace(s, "  name: baseline", "  name: \"\"", 1) },
			want:  "metadata.name",
			fatal: true,
		},
		{
			name: "unknown effect",
			// A typo in an effect must not be treated as an unrecognised-and-ignored
			// rule; the whole rule becomes meaningless.
			mutch: func(s string) string { return strings.Replace(s, "effect: deny", "effect: denny", 1) },
			want:  "unknown effect",
			fatal: true,
		},
		{
			name:  "typo in a match path",
			mutch: func(s string) string { return strings.Replace(s, "action.name:", "action.nmae:", 1) },
			want:  "not a known ActionIntent path",
			fatal: false, // context.* is open, so unknown paths are a warning
		},
		{
			name: "effect the local engine cannot enforce",
			// Accepted for compatibility with the enterprise plane, but it must be
			// reported rather than silently behaving like allow.
			mutch: func(s string) string { return strings.Replace(s, "effect: deny", "effect: require_approval", 1) },
			want:  "not supported by the local engine",
			fatal: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := policy.Parse([]byte(tc.mutch(valid)))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			probs := policy.Validate(p)
			if !mentions(probs, tc.want) {
				t.Fatalf("expected a problem mentioning %q, got %v", tc.want, probs)
			}
			if policy.Fatal(probs) != tc.fatal {
				t.Errorf("fatal = %v, want %v (%v)", policy.Fatal(probs), tc.fatal, probs)
			}
		})
	}
}

func TestValidateRejectsDuplicateRuleIDsAndEmptyMatch(t *testing.T) {
	t.Parallel()

	src := `
apiVersion: guard.unveilr.ai/v1alpha1
kind: Policy
metadata:
  name: broken
spec:
  rules:
    - id: dup
      match:
        action.name: a
      effect: deny
    - id: dup
      match:
        action.name: b
      effect: allow
    - id: catch-all
      match: {}
      effect: allow
`
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	probs := policy.Validate(p)
	if !mentions(probs, "duplicate rule id") {
		t.Error("duplicate rule ids must be rejected: a decision citing rule 'dup' is unexplainable")
	}
	if !mentions(probs, "at least one field") {
		t.Error("a rule with an empty match would apply to every action")
	}
	if !policy.Fatal(probs) {
		t.Error("expected these to be fatal")
	}
}

func TestValidateReportsEveryProblemNotJustTheFirst(t *testing.T) {
	t.Parallel()

	src := strings.NewReplacer(
		schema.APIVersion, "wrong",
		"  name: baseline", "  name: \"\"",
	).Replace(valid)

	p, _ := policy.Parse([]byte(src))
	if n := len(policy.Validate(p)); n < 2 {
		t.Errorf("got %d problems, want at least 2; fixing policies one error per run is miserable", n)
	}
}

func TestSetHashIsStableAndOrderIndependent(t *testing.T) {
	t.Parallel()

	// The hash is pinned into every Decision so it can be replayed against
	// exactly the rules that produced it. If load order changed the hash, two
	// engines with identical policies would disagree about what they evaluated.
	a, _ := policy.Parse([]byte(valid))
	b, _ := policy.Parse([]byte(strings.Replace(valid, "  name: baseline", "  name: second", 1)))

	if policy.SetHash([]policy.Policy{a, b}) != policy.SetHash([]policy.Policy{b, a}) {
		t.Error("hash depends on policy order")
	}
	if policy.SetHash([]policy.Policy{a}) == policy.SetHash([]policy.Policy{a, b}) {
		t.Error("adding a policy did not change the hash")
	}
	if policy.SetHash(nil) == "" {
		t.Error("empty set must still hash, so 'no policies' is a recordable state")
	}

	// Same rules, different match-key order in the source.
	reordered := `
apiVersion: guard.unveilr.ai/v1alpha1
kind: Policy
metadata:
  name: baseline
spec:
  rules:
    - id: no-passrole
      description: iam:PassRole is privilege escalation in one call
      match:
        action.name: iam:PassRole
      effect: deny
`
	c, _ := policy.Parse([]byte(reordered))
	if policy.SetHash([]policy.Policy{a}) != policy.SetHash([]policy.Policy{c}) {
		t.Error("semantically identical policies hashed differently")
	}
}

func mentions(ps []policy.Problem, substr string) bool {
	for _, p := range ps {
		if strings.Contains(p.Message, substr) {
			return true
		}
	}
	return false
}
