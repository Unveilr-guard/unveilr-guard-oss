// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package policy is the policy-as-code contract: the YAML shape users author,
// and the parsing and validation around it.
//
// It is deliberately not a programming language. `match` is a set of equality or
// set-membership constraints over dotted paths into an ActionIntent, evaluated
// deterministically. Expressiveness is the enemy of validatability, and a
// decision that cannot be replayed cannot be evidence.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/unveilr/unveilr-guard/pkg/schema"
)

// Policy is one authored policy document.
type Policy struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind"       json:"kind"`
	Metadata   Metadata `yaml:"metadata"   json:"metadata"`
	Spec       Spec     `yaml:"spec"       json:"spec"`
}

// Metadata names the policy.
type Metadata struct {
	Name        string `yaml:"name"                  json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version,omitempty"     json:"version,omitempty"`
}

// Spec holds the rules.
type Spec struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Rule is one match/effect pair.
type Rule struct {
	ID          string `yaml:"id"                    json:"id"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Match maps dotted ActionIntent paths to an expected value. A scalar
	// matches exactly; a sequence matches set membership. All keys must match.
	Match  map[string]Matcher `yaml:"match"  json:"match"`
	Effect schema.Effect      `yaml:"effect" json:"effect"`
}

// Matcher is a scalar or a list, so `action.name: iam:PassRole` and
// `action.name: [a, b]` are both natural to write.
type Matcher struct {
	Values []string
}

// UnmarshalYAML accepts either form.
func (m *Matcher) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		m.Values = []string{s}
		return nil
	case yaml.SequenceNode:
		var xs []string
		if err := n.Decode(&xs); err != nil {
			return err
		}
		if len(xs) == 0 {
			return fmt.Errorf("empty list: a matcher must constrain something")
		}
		m.Values = xs
		return nil
	default:
		return fmt.Errorf("expected a string or a list of strings")
	}
}

// Matches reports whether v satisfies the matcher.
func (m Matcher) Matches(v string) bool {
	for _, want := range m.Values {
		if want == v {
			return true
		}
	}
	return false
}

// Parse reads one policy document.
func Parse(data []byte) (Policy, error) {
	var p Policy
	// KnownFields makes an unrecognised key an error rather than silence. A
	// misspelled `effect:` that parses to nothing would otherwise produce a
	// policy that quietly never denies — the worst possible failure here.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse: %w", err)
	}
	return p, nil
}

// Problem is a validation failure. Fatal problems make a policy unusable;
// non-fatal ones are reported but do not block evaluation.
type Problem struct {
	Rule    string
	Message string
	Fatal   bool
}

func (p Problem) String() string {
	where := "policy"
	if p.Rule != "" {
		where = "rule " + p.Rule
	}
	return fmt.Sprintf("%s: %s", where, p.Message)
}

// Validate checks structure and semantics. It reports every problem rather than
// stopping at the first, because fixing policies one error per run is miserable.
func Validate(p Policy) []Problem {
	var out []Problem
	add := func(rule, msg string, fatal bool) {
		out = append(out, Problem{Rule: rule, Message: msg, Fatal: fatal})
	}

	if p.APIVersion != schema.APIVersion {
		add("", fmt.Sprintf("apiVersion must be %q, got %q", schema.APIVersion, p.APIVersion), true)
	}
	if p.Kind != schema.KindPolicy {
		add("", fmt.Sprintf("kind must be %q, got %q", schema.KindPolicy, p.Kind), true)
	}
	if strings.TrimSpace(p.Metadata.Name) == "" {
		add("", "metadata.name is required", true)
	}
	if len(p.Spec.Rules) == 0 {
		add("", "spec.rules must contain at least one rule", true)
	}

	seen := map[string]bool{}
	for _, r := range p.Spec.Rules {
		switch {
		case strings.TrimSpace(r.ID) == "":
			add("", "every rule needs an id", true)
			continue
		case seen[r.ID]:
			// Duplicate ids make a decision ambiguous to explain afterwards.
			add(r.ID, "duplicate rule id", true)
			continue
		}
		seen[r.ID] = true

		if len(r.Match) == 0 {
			// A rule matching everything is almost always a mistake, and if it
			// is deliberate it should say so with an explicit wildcard field.
			add(r.ID, "match must constrain at least one field", true)
		}
		for k := range r.Match {
			if !knownPath(k) {
				// Not fatal: the intent shape is open (context is free-form), so
				// an unknown path may be intentional. But a typo like
				// `action.nmae` silently never matches, which is worth flagging.
				add(r.ID, fmt.Sprintf("match key %q is not a known ActionIntent path; it will never match unless the adapter sets it", k), false)
			}
		}

		if r.Effect == "" {
			add(r.ID, "effect is required", true)
			continue
		}
		if !knownEffect(r.Effect) {
			add(r.ID, fmt.Sprintf("unknown effect %q", r.Effect), true)
			continue
		}
		if !schema.LocallySupported(r.Effect) {
			// Accepted for schema compatibility with the enterprise plane, but
			// reported. Silently downgrading it to allow would be far worse.
			add(r.ID, fmt.Sprintf("effect %q is not supported by the local engine; it is accepted for compatibility and will be reported as unsupported rather than enforced", r.Effect), false)
		}
	}
	return out
}

// Fatal reports whether any problem blocks use of the policy.
func Fatal(ps []Problem) bool {
	for _, p := range ps {
		if p.Fatal {
			return true
		}
	}
	return false
}

func knownEffect(e schema.Effect) bool {
	if e == schema.EffectWarn {
		return true
	}
	for _, p := range schema.Precedence {
		if p == e {
			return true
		}
	}
	// `quarantine` is reserved for the enterprise protocol. Recognised so a
	// policy written for enterprise parses locally, then reported as unsupported.
	return e == "quarantine"
}

// knownPaths are the dotted paths the evaluator can resolve. `context.*` is
// open by design, so it is handled by prefix.
var knownPaths = map[string]bool{
	"agent.id": true, "agent.type": true, "agent.version": true,
	"actor.type": true, "actor.id": true, "actor.clientApplication": true,
	"action.type": true, "action.provider": true, "action.name": true,
	"resource.type": true, "resource.id": true, "resource.dataClasses": true,
}

func knownPath(k string) bool {
	return knownPaths[k] || strings.HasPrefix(k, "context.")
}

// SetHash is a stable hash of a policy set, pinned into every Decision so the
// decision can be replayed against exactly the rules that produced it.
//
// Order-independent: two engines loading the same policies in a different order
// must produce the same hash, or the guarantee is worthless.
func SetHash(ps []Policy) string {
	lines := make([]string, 0, len(ps))
	for _, p := range ps {
		for _, r := range p.Spec.Rules {
			keys := make([]string, 0, len(r.Match))
			for k := range r.Match {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var b strings.Builder
			fmt.Fprintf(&b, "%s|%s|%s|", p.Metadata.Name, r.ID, r.Effect)
			for _, k := range keys {
				vs := append([]string(nil), r.Match[k].Values...)
				sort.Strings(vs)
				fmt.Fprintf(&b, "%s=%s;", k, strings.Join(vs, ","))
			}
			lines = append(lines, b.String())
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}
