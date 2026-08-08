// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"regexp"
	"strings"
)

// Discovered server commands routinely embed live credentials — an MCP config
// carries "--figma-api-key=figd_…" or "--token sk-…" as a matter of course,
// because the config exists to authenticate the server, not to be displayed.
//
// Scan()'s output goes to three places: a terminal, `--json` (which a script
// might pipe into a file or a CI log), and RegisterServer (which uploads it to
// the SaaS). None of those are places a live secret should land (SG-01, SG-02,
// SG-11). Redaction happens HERE, once, at construction — not at each call
// site — so nothing that consumes a Server can forget to do it, including
// callers that do not exist yet.
//
// What survives redaction is deliberately the flag NAME, not the value: "this
// server holds an API key" is exactly the governance-relevant fact discovery
// exists to surface (an unregistered credential is one of the findings E0 is
// testing for) — only the value is dangerous, not the shape.

const redacted = "[REDACTED]"

// secretFlagName matches a flag whose NAME says it carries a credential,
// regardless of vendor: --figma-api-key, --token, --auth-secret, -p (password
// is spelled out, not abbreviated, to avoid matching ordinary short flags).
var secretFlagName = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|credential)`)

// secretValueShape is a fallback for a value that is clearly a live credential
// even when the flag beside it is not obviously named (a bare positional
// argument, or a vendor prefix we recognise on sight).
var secretValueShape = regexp.MustCompile(`^(sk-|pk_live_|gh[pousr]_|figd_|xox[baprs]-|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)

// redactArgs returns a copy of args with credential-shaped values replaced.
// It never mutates the input, so the caller can still hold the real slice
// where that is legitimate (the proxy adapter execs the real, un-redacted
// command it was given directly on the CLI — it never goes through Scan()).
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)

	for i, a := range out {
		if key, val, ok := splitFlagValue(a); ok {
			if secretFlagName.MatchString(key) || secretValueShape.MatchString(val) {
				out[i] = key + "=" + redacted
			}
			continue
		}
		// Two-token form: `--api-key figd_xxx` as adjacent args. Only treat
		// this arg as the flag if it looks like one — otherwise an ordinary
		// positional value that happens to contain "token" would blank out
		// whatever follows it.
		if looksLikeFlag(a) && secretFlagName.MatchString(a) && i+1 < len(out) {
			out[i+1] = redacted
			continue
		}
		if secretValueShape.MatchString(a) {
			out[i] = redacted
		}
	}
	return out
}

func looksLikeFlag(s string) bool {
	return strings.HasPrefix(s, "-")
}

// splitFlagValue splits "--flag=value" or "flag=value" (bare env-style
// assignment, e.g. an arg like "FIGMA_API_KEY=figd_xxx"). A value is only
// split out when there IS an '=' — "--verbose" has no value to redact.
func splitFlagValue(s string) (key, val string, ok bool) {
	idx := strings.Index(s, "=")
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
