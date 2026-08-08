// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"strings"
	"testing"
)

// Found live: a real Cursor config on a real machine produced
// `--figma-api-key=figd_…` verbatim in `unveilr-shield scan --json`, in
// violation of SG-01 ("never expose credential secret values in CLI output").
// The same unredacted Args also flow into RegisterServer, which uploads them to
// the SaaS — a second, worse instance of the same root cause (SG-02: never
// upload credentials by default). These cases fix the specific failure found,
// then generalise it.

func TestRedactArgsCatchesTheLeakThatWasFound(t *testing.T) {
	t.Parallel()

	// The exact shape of the real leak (synthetic value, same structure).
	in := []string{"-y", "figma-developer-mcp", "--figma-api-key=figd_ExampleNotARealKey00000000"}
	got := redactArgs(in)

	if got[2] != "--figma-api-key="+redacted {
		t.Fatalf("flag name should survive, value should not: got %q", got[2])
	}
	if strings.Contains(strings.Join(got, " "), "figd_") {
		t.Fatal("the secret value leaked through redaction")
	}
	if got[0] != "-y" || got[1] != "figma-developer-mcp" {
		t.Errorf("non-secret args must survive unchanged: %v", got)
	}
}

func TestRedactArgsCoversCommonCredentialShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{"equals form, named flag", []string{"--api-key=sk-abcdefghijklmnopqrstuvwx"}},
		{"equals form, token", []string{"--token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
		{"two-token form", []string{"--api-key", "sk-abcdefghijklmnopqrstuvwx"}},
		{"short env-style assignment arg", []string{"FIGMA_API_KEY=figd_abcdefghijklmnopqrstuvwx"}},
		{"password flag", []string{"--password=hunter2ButLongerThanThat"}},
		{"bare AWS key with no flag name at all", []string{"AKIAIOSFODNN7EXAMPLE"}},
		{"bearer-style secret value, unnamed flag", []string{"--header", "figd_abcdefghijklmnopqrstuvwx"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := redactArgs(tc.args)
			joined := strings.Join(got, " ")
			for _, secret := range []string{"sk-abcdefghijklmnopqrstuvwx", "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
				"figd_abcdefghijklmnopqrstuvwx", "hunter2ButLongerThanThat", "AKIAIOSFODNN7EXAMPLE"} {
				if strings.Contains(joined, secret) {
					t.Errorf("case %q: secret leaked through: %v", tc.name, got)
				}
			}
		})
	}
}

func TestRedactArgsLeavesOrdinaryArgsAlone(t *testing.T) {
	t.Parallel()

	// A discovery tool that redacts everything protects nothing usefully — an
	// operator still needs to see which server is which and how it is invoked.
	in := []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects", "--verbose", "--port=8811"}
	got := redactArgs(in)

	for i, want := range in {
		if got[i] != want {
			t.Errorf("arg %d changed unexpectedly: %q -> %q", i, want, got[i])
		}
	}
}

func TestRedactArgsDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	// proxy.go execs the REAL command with the REAL args it was given directly
	// on the CLI — never through Scan(). If redactArgs mutated its input in
	// place, a future caller sharing a backing array with that path would
	// silently corrupt the credential the child process needs to authenticate.
	in := []string{"--api-key=sk-abcdefghijklmnopqrstuvwx"}
	original := append([]string(nil), in...)

	_ = redactArgs(in)

	for i := range in {
		if in[i] != original[i] {
			t.Fatalf("input was mutated: %v", in)
		}
	}
}

func TestScanNeverReturnsASecretValue(t *testing.T) {
	t.Parallel()

	// End-to-end through Scan() itself is what the CLI and RegisterServer
	// actually call — a passing redactArgs test with a forgotten call site in
	// discovery.go would not have caught the original bug.
	servers := Scan()
	for _, s := range servers {
		for _, a := range s.Args {
			if secretValueShape.MatchString(a) {
				t.Errorf("Scan() returned an unredacted-looking value for %q: %q", s.Name, a)
			}
		}
		if secretValueShape.MatchString(s.URL) {
			t.Errorf("Scan() returned an unredacted-looking URL for %q: %q", s.Name, s.URL)
		}
	}
}

func TestRedactURLStripsUserinfo(t *testing.T) {
	t.Parallel()
	got := redactURL("https://user:secretpass@mcp.example.com/mcp")
	if strings.Contains(got, "secretpass") {
		t.Fatalf("userinfo leaked: %q", got)
	}
}

func TestRedactURLRedactsCredentialShapedQueryParams(t *testing.T) {
	t.Parallel()
	got := redactURL("https://mcp.example.com/mcp?api_key=sk-abcdefghijklmnopqrstuvwx&region=us")
	if strings.Contains(got, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("query-param secret leaked: %q", got)
	}
	if !strings.Contains(got, "region=us") {
		t.Errorf("ordinary query param should survive: %q", got)
	}
}

func TestRedactURLLeavesAnOrdinaryURLAlone(t *testing.T) {
	t.Parallel()
	const in = "https://mcp.workos.com/mcp"
	if got := redactURL(in); got != in {
		t.Errorf("got %q, want unchanged %q", got, in)
	}
}

func TestRedactURLHandlesAnEmptyURL(t *testing.T) {
	t.Parallel()
	if got := redactURL(""); got != "" {
		t.Errorf("got %q, want empty (stdio servers have no URL)", got)
	}
}
