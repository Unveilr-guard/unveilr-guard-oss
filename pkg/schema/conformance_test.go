// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/unveilr/unveilr-guard/pkg/schema"
)

// Unveilr now has THREE implementations of effect combination: this one, the
// enterprise Python PDP, and the TypeScript MCP gateway. "The same decision
// everywhere" is the product claim; without a shared fixture set run against all
// three it is unfalsifiable. conformance/effects.json is that fixture set — the
// same file the other two engines are tested against.
//
// A divergence here is not a cosmetic test failure. It means an action denied at
// one enforcement point is permitted at another.

type fixtures struct {
	Version    int             `json:"version"`
	Precedence []schema.Effect `json:"precedence"`
	Pairs      []struct {
		Name string        `json:"name"`
		A    schema.Effect `json:"a"`
		B    schema.Effect `json:"b"`
		Want schema.Effect `json:"want"`
		Why  string        `json:"why"`
	} `json:"pairs"`
	Sets []struct {
		Name    string          `json:"name"`
		Effects []schema.Effect `json:"effects"`
		Want    schema.Effect   `json:"want"`
		Why     string          `json:"why"`
	} `json:"sets"`
	UnknownEffects struct {
		EnforcedBy []string `json:"enforcedBy"`
		Cases      []struct {
			Name    string        `json:"name"`
			A       schema.Effect `json:"a"`
			B       schema.Effect `json:"b"`
			WantNot schema.Effect `json:"wantNot"`
			Why     string        `json:"why"`
		} `json:"cases"`
	} `json:"unknownEffects"`
}

func load(t *testing.T) fixtures {
	t.Helper()
	path := filepath.Join("..", "..", "conformance", "effects.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var f fixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(f.Pairs) == 0 || len(f.Sets) == 0 {
		t.Fatal("fixture file loaded but is empty; a vacuously passing conformance suite is worse than none")
	}
	return f
}

func TestPrecedenceMatchesFixtures(t *testing.T) {
	f := load(t)

	if len(f.Precedence) != len(schema.Precedence) {
		t.Fatalf("precedence length: fixtures %d, engine %d", len(f.Precedence), len(schema.Precedence))
	}
	for i := range f.Precedence {
		if f.Precedence[i] != schema.Precedence[i] {
			t.Errorf("precedence[%d]: fixtures %q, engine %q", i, f.Precedence[i], schema.Precedence[i])
		}
	}
}

func TestPairCombinationMatchesFixtures(t *testing.T) {
	f := load(t)

	for _, c := range f.Pairs {
		if got := schema.MoreRestrictive(c.A, c.B); got != c.Want {
			t.Errorf("%s: MoreRestrictive(%q,%q) = %q, want %q\n  why it matters: %s",
				c.Name, c.A, c.B, got, c.Want, c.Why)
		}
	}
}

func TestExhaustivePairsAreCommutativeAndOrdered(t *testing.T) {
	f := load(t)

	// Derived from the FIXTURE ordering against the ENGINE function, so this is a
	// drift test rather than a tautology: the engine keeps its own copy of the
	// order and the two must agree on all 49 pairs, not just the curated ones.
	for i, a := range f.Precedence {
		for j, b := range f.Precedence {
			want := a
			if j > i {
				want = b
			}
			if got := schema.MoreRestrictive(a, b); got != want {
				t.Errorf("MoreRestrictive(%q,%q) = %q, want %q", a, b, got, want)
			}
			if fwd, rev := schema.MoreRestrictive(a, b), schema.MoreRestrictive(b, a); fwd != rev {
				t.Errorf("not commutative for (%q,%q): %q vs %q", a, b, fwd, rev)
			}
		}
	}
}

func TestSetCombinationMatchesFixtures(t *testing.T) {
	f := load(t)

	for _, c := range f.Sets {
		if len(c.Effects) == 0 {
			t.Errorf("%s: empty effect set in fixtures", c.Name)
			continue
		}
		got := c.Effects[0]
		for _, e := range c.Effects[1:] {
			got = schema.MoreRestrictive(got, e)
		}
		if got != c.Want {
			t.Errorf("%s: combined %v = %q, want %q\n  why it matters: %s", c.Name, c.Effects, got, c.Want, c.Why)
		}
	}
}

func TestAddingAPolicyNeverWidensAccess(t *testing.T) {
	f := load(t)

	// The property the whole precedence table exists to provide. Stated directly
	// so it survives someone "simplifying" the table.
	for _, a := range f.Precedence {
		for _, b := range f.Precedence {
			combined := schema.MoreRestrictive(a, b)
			ia, ib := indexOf(f.Precedence, a), indexOf(f.Precedence, b)
			ic := indexOf(f.Precedence, combined)
			if ic < ia || ic < ib {
				t.Errorf("combining %q and %q produced %q, which is weaker than an input", a, b, combined)
			}
		}
	}
}

func TestUnknownEffectFailsClosed(t *testing.T) {
	f := load(t)

	// The one place the three engines are known to disagree. Go fails closed;
	// the fixture records that, and records that Go is currently the only engine
	// asserted against it. See conformance/README.md.
	if !contains(f.UnknownEffects.EnforcedBy, "go") {
		t.Fatal("fixtures no longer list go as enforcing unknown-effect behaviour; this test would be asserting nothing")
	}
	for _, c := range f.UnknownEffects.Cases {
		if got := schema.MoreRestrictive(c.A, c.B); got == c.WantNot {
			t.Errorf("%s: MoreRestrictive(%q,%q) = %q — an unrecognised effect was discarded in favour of the permissive one\n  why it matters: %s",
				c.Name, c.A, c.B, got, c.Why)
		}
		// Commutativity must hold for unknowns too, or the outcome depends on
		// policy load order.
		if fwd, rev := schema.MoreRestrictive(c.A, c.B), schema.MoreRestrictive(c.B, c.A); fwd != rev {
			t.Errorf("%s: not commutative: %q vs %q", c.Name, fwd, rev)
		}
	}
}

func TestLocallySupportedIsHonestAboutWhatThisBuildCanDo(t *testing.T) {
	// Claiming local support for an effect this build cannot carry out would make
	// the guard report enforcement that never happened — the single worst bug
	// this product can have (SG-07).
	for _, e := range []schema.Effect{
		schema.EffectRedact, schema.EffectSanitize, schema.EffectScopedToken,
		schema.EffectRequireApproval, schema.EffectStepUp,
	} {
		if schema.LocallySupported(e) {
			t.Errorf("%q reported as locally supported, but no local mechanism implements it", e)
		}
	}
	for _, e := range []schema.Effect{schema.EffectAllow, schema.EffectDeny, schema.EffectWarn} {
		if !schema.LocallySupported(e) {
			t.Errorf("%q must be supported locally", e)
		}
	}
}

func indexOf(xs []schema.Effect, x schema.Effect) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
