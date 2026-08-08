// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package agent fingerprints locally-installed coding-agent tooling.
//
// The README's own pitch leads with three questions: how many agents do we
// have, what can they reach, who owns them. Package mcp (a sibling of this
// one) answers "what can they reach" for MCP servers; this answers the first.
// Ported from the enterprise SDK's unveilr.discover.detect_installed_agents —
// same evidence, same discipline: presence only, kept to signals with a low
// false-positive rate. A bare ~/.vscode directory is not Copilot; most VS
// Code users have neither.
package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
)

// Agent is one detected coding-agent installation.
type Agent struct {
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
}

type check struct {
	name  string
	found func() string // returns evidence, or "" if not found
}

func checkBinary(bin string) func() string {
	return func() string {
		if _, err := exec.LookPath(bin); err == nil {
			return "binary:" + bin
		}
		return ""
	}
}

func checkPath(p string) func() string {
	return func() string {
		if _, err := os.Stat(p); err == nil {
			return "path:" + p
		}
		return ""
	}
}

// checkGlob reports the first child of base matching pattern (e.g. VS Code
// extension directories, which are versioned: github.copilot-1.234.0).
func checkGlob(base, pattern string) func() string {
	return func() string {
		entries, err := os.ReadDir(base)
		if err != nil {
			return ""
		}
		for _, e := range entries {
			if ok, _ := filepath.Match(pattern, e.Name()); ok {
				return "path:" + filepath.Join(base, e.Name())
			}
		}
		return ""
	}
}

func claudeDesktopConfigPath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

func checks() []check {
	home, _ := os.UserHomeDir()
	return []check{
		{"claude-code", checkBinary("claude")},
		{"claude-code", checkPath(filepath.Join(home, ".claude"))},
		{"claude-desktop", checkPath(claudeDesktopConfigPath())},
		{"cursor", checkPath(filepath.Join(home, ".cursor"))},
		{"github-copilot", checkGlob(filepath.Join(home, ".vscode", "extensions"), "github.copilot-*")},
	}
}

// Detect fingerprints locally-installed coding-agent tooling.
//
// Each named agent appears at most once, keeping its first (strongest)
// evidence — a binary on PATH is checked before a config directory for the
// same agent, since a stale leftover directory from an uninstalled tool is
// weaker evidence than an executable that still runs. Results are sorted by
// name for a deterministic order.
func Detect() []Agent {
	seen := map[string]string{}
	order := []string{}
	for _, c := range checks() {
		if _, ok := seen[c.name]; ok {
			continue
		}
		if ev := c.found(); ev != "" {
			seen[c.name] = ev
			order = append(order, c.name)
		}
	}
	sort.Strings(order)
	out := make([]Agent, 0, len(order))
	for _, name := range order {
		out = append(out, Agent{Name: name, Evidence: seen[name]})
	}
	return out
}
