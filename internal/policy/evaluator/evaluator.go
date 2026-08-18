// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package evaluator decides an ActionIntent against a policy set.
//
// Two properties carry everything else:
//
//   - Deterministic. The same intent and the same policies always produce the
//     same decision, including the order of reason codes. A decision that cannot
//     be reproduced cannot be evidence.
//   - Forbid-overrides. The most restrictive matching effect wins, so ADDING a
//     policy can never widen access. An operator can add a rule without
//     re-auditing every existing one.
package evaluator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.unveilr.ai/guard/pkg/policy"
	"go.unveilr.ai/guard/pkg/schema"
)

// EngineName identifies decisions produced locally, as opposed to ones returned
// by the enterprise plane.
const EngineName = "unveilr-guard-local"

// Evaluator decides intents. An interface so the same call site can later target
// a remote PDP over HTTPS without changing the action schema (ADR-002).
type Evaluator interface {
	Evaluate(ctx context.Context, intent schema.ActionIntent, policies []policy.Policy) (schema.Decision, error)
}

// Local evaluates entirely on this machine. It never makes a network call, so
// losing connectivity cannot change a local decision (ADR-003).
type Local struct {
	Version string
	// Default applies when no rule matches. Deny is the safe value, but the
	// local guard defaults to allow: it sits in front of a developer's own tools
	// and a default-deny local proxy would break every unmatched call and be
	// switched off within a day. Deny-by-default belongs to the enterprise
	// plane, where the estate is known.
	Default schema.Effect
	// Now is injectable so tests are deterministic.
	Now func() time.Time
}

// New returns a Local evaluator with production defaults.
func New(version string) *Local {
	return &Local{Version: version, Default: schema.EffectAllow, Now: time.Now}
}

// Evaluate applies the policy set to one intent.
func (l *Local) Evaluate(_ context.Context, intent schema.ActionIntent, policies []policy.Policy) (schema.Decision, error) {
	now := l.Now
	if now == nil {
		now = time.Now
	}
	def := l.Default
	if def == "" {
		def = schema.EffectAllow
	}

	d := schema.Decision{
		APIVersion: schema.APIVersion,
		Kind:       schema.KindDecision,
		IntentID:   intent.ID,
		Timestamp:  now().UTC().Format(time.RFC3339),
		Engine: schema.Engine{
			Name:          EngineName,
			Version:       l.Version,
			PolicySetHash: policy.SetHash(policies),
		},
	}

	if len(policies) == 0 {
		// Distinct from "nothing matched": no policies loaded usually means a
		// configuration mistake, and an operator should be able to tell the two
		// apart from the decision alone.
		d.Effect = def
		d.SupportedLocally = schema.LocallySupported(def)
		d.Reason = "no policies loaded; applying the default effect"
		d.ReasonCodes = []string{schema.CodeNoPoliciesLoaded}
		return d, nil
	}

	type hit struct {
		policy string
		rule   string
		effect schema.Effect
		desc   string
	}
	var hits []hit

	for _, p := range policies {
		for _, r := range p.Spec.Rules {
			if !ruleMatches(r, intent) {
				continue
			}
			hits = append(hits, hit{p.Metadata.Name, r.ID, r.Effect, r.Description})
		}
	}

	if len(hits) == 0 {
		d.Effect = def
		d.SupportedLocally = schema.LocallySupported(def)
		d.Reason = fmt.Sprintf("no rule matched; applying the default effect %q", def)
		d.ReasonCodes = []string{schema.CodeNoPolicyMatched}
		return d, nil
	}

	// Deterministic ordering before combination, so the winning rule reported
	// for two equally-restrictive matches is stable across runs and machines.
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].policy != hits[j].policy {
			return hits[i].policy < hits[j].policy
		}
		return hits[i].rule < hits[j].rule
	})

	winner := hits[0]
	effect := winner.effect
	for _, h := range hits[1:] {
		if merged := schema.MoreRestrictive(effect, h.effect); merged != effect {
			effect, winner = merged, h
		}
	}

	d.Effect = effect
	d.SupportedLocally = schema.LocallySupported(effect)
	d.MatchedPolicy = winner.policy
	d.MatchedRule = winner.rule

	reason := winner.desc
	if strings.TrimSpace(reason) == "" {
		reason = fmt.Sprintf("matched rule %q in policy %q", winner.rule, winner.policy)
	}

	switch {
	case !d.SupportedLocally:
		// Never silently downgrade to allow. The caller must be able to tell
		// "policy says require approval and I cannot do that" from "allowed".
		d.Reason = fmt.Sprintf("%s — effect %q requires the Unveilr enterprise plane and is not enforced locally", reason, effect)
		d.ReasonCodes = []string{schema.CodeEffectUnsupported}
	case effect == schema.EffectDeny:
		d.Reason = reason
		d.ReasonCodes = []string{schema.CodePolicyDeny}
	case effect == schema.EffectWarn:
		d.Reason = reason
		d.ReasonCodes = []string{schema.CodePolicyWarn}
	default:
		d.Reason = reason
	}
	return d, nil
}

// ruleMatches reports whether every constraint in the rule holds. All keys must
// match (AND); a rule with no constraints never matches, which validation
// already rejects but is re-checked here so a hand-built Rule cannot match
// everything by accident.
func ruleMatches(r policy.Rule, in schema.ActionIntent) bool {
	if len(r.Match) == 0 {
		return false
	}
	for path, m := range r.Match {
		vals, ok := resolve(in, path)
		if !ok {
			return false
		}
		// A multi-valued field (dataClasses) matches if ANY of its values does:
		// a resource carrying `secrets` should match a rule about secrets even
		// when it also carries other classes.
		any := false
		for _, v := range vals {
			if m.Matches(v) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	return true
}

// resolve reads a dotted path out of an intent. It returns ok=false for an
// absent field so an unmatched path fails the rule rather than matching "".
func resolve(in schema.ActionIntent, path string) ([]string, bool) {
	str := func(s string) ([]string, bool) {
		if s == "" {
			return nil, false
		}
		return []string{s}, true
	}

	switch path {
	case "agent.id":
		return str(in.Agent.ID)
	case "agent.type":
		return str(in.Agent.Type)
	case "agent.version":
		return str(in.Agent.Version)
	case "action.type":
		return str(in.Action.Type)
	case "action.provider":
		return str(in.Action.Provider)
	case "action.name":
		return str(in.Action.Name)
	}

	if in.Actor != nil {
		switch path {
		case "actor.type":
			return str(in.Actor.Type)
		case "actor.id":
			return str(in.Actor.ID)
		case "actor.clientApplication":
			return str(in.Actor.ClientApplication)
		}
	}
	if in.Resource != nil {
		switch path {
		case "resource.type":
			return str(in.Resource.Type)
		case "resource.id":
			return str(in.Resource.ID)
		case "resource.dataClasses":
			if len(in.Resource.DataClasses) == 0 {
				return nil, false
			}
			return in.Resource.DataClasses, true
		}
	}

	if key, ok := strings.CutPrefix(path, "context."); ok {
		v, present := in.Context[key]
		if !present {
			return nil, false
		}
		if s, isStr := v.(string); isStr {
			return str(s)
		}
		return str(fmt.Sprint(v))
	}
	return nil, false
}
