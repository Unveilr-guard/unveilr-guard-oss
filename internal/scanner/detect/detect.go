// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package detect is a lightweight local mirror of the gateway's detection
// engine (@unveilr/shared). It runs offline in the Local Shield so a local MCP
// call can be blocked/flagged even when the SaaS is unreachable.
package detect

import "regexp"

type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Rule     string `json:"rule"`
}

type rule struct {
	re       *regexp.Regexp
	category string
	severity string
	message  string
	id       string
}

var rules = []rule{
	{regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,20}\b(instructions?|prompts?|rules?)\b`), "prompt_injection", "high", "Attempt to override prior instructions", "PI-001"},
	{regexp.MustCompile(`(?i)\bdo not\b.{0,20}\b(tell|inform|mention|notify)\b.{0,20}\b(the )?(user|human|anyone)\b`), "prompt_injection", "high", "Instruction to hide behavior from the user", "PI-004"},
	{regexp.MustCompile(`(?:^|[^A-Za-z0-9])\.\.[\/\\]`), "path_traversal", "high", "Relative path traversal sequence", "PT-001"},
	{regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)|\.ssh/|\.aws/credentials|(?:^|/)\.env(?:[."\s]|$)`), "path_traversal", "critical", "Access to a sensitive system or credential path", "PT-003"},
	{regexp.MustCompile(`(?i)\brm\s+-rf?\b|(curl|wget)\b[^\n|]{0,200}\|\s*(sh|bash|zsh)\b|>\s*/dev/tcp/`), "command_injection", "critical", "Destructive or reverse-shell command pattern", "CI-002"},
	{regexp.MustCompile(`\$\([^)]{1,200}\)|` + "`" + `[^` + "`" + `]{1,200}` + "`"), "command_injection", "high", "Shell command substitution", "CI-001"},
	{regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b|\bOR\s+1\s*=\s*1\b|;\s*(DROP|DELETE|TRUNCATE)\s+(TABLE|FROM)`), "sql_injection", "high", "SQL injection pattern", "SQLI"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "secret_leak", "critical", "AWS access key id", "SEC-AWS"},
	{regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), "secret_leak", "critical", "Private key block", "SEC-PK"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), "secret_leak", "critical", "GitHub access token", "SEC-GH"},
	{regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "pii", "low", "Email address", "PII-EMAIL"},
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "pii", "high", "US Social Security Number", "PII-SSN"},
}

var severityScore = map[string]int{"info": 1, "low": 5, "medium": 12, "high": 25, "critical": 40}

// Scan returns findings and an aggregate 0..100 risk score for a string.
func Scan(text string) ([]Finding, int) {
	var findings []Finding
	score := 0
	seen := map[string]int{}
	for _, r := range rules {
		if r.re.MatchString(text) {
			findings = append(findings, Finding{r.category, r.severity, r.message, r.id})
			decay := 1.0 / (1.0 + float64(seen[r.category])*0.5)
			score += int(float64(severityScore[r.severity]) * decay)
			seen[r.category]++
		}
	}
	if score > 100 {
		score = 100
	}
	return findings, score
}
