// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package discovery finds locally-configured MCP servers across the common
// client config locations (Claude Desktop, Cursor, VS Code, project .mcp.json).
package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

type Server struct {
	Name      string   `json:"name"`
	Source    string   `json:"source"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	URL       string   `json:"url,omitempty"`
	Transport string   `json:"transport"`
}

type mcpConfigFile struct {
	McpServers map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
		URL     string   `json:"url"`
		Type    string   `json:"type"`
	} `json:"mcpServers"`
}

// candidatePaths returns config files to inspect, OS-aware.
func candidatePaths() map[string]string {
	home, _ := os.UserHomeDir()
	paths := map[string]string{
		"project": ".mcp.json",
		"cursor":  filepath.Join(home, ".cursor", "mcp.json"),
		"vscode":  filepath.Join(home, ".vscode", "mcp.json"),
	}
	switch runtime.GOOS {
	case "darwin":
		paths["claude-desktop"] = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		paths["claude-desktop"] = filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
	default:
		paths["claude-desktop"] = filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
	return paths
}

// Scan reads all candidate config files and returns the discovered servers.
func Scan() []Server {
	var out []Server
	for source, path := range candidatePaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg mcpConfigFile
		if json.Unmarshal(data, &cfg) != nil {
			continue
		}
		for name, s := range cfg.McpServers {
			transport := "stdio"
			if s.URL != "" {
				transport = "streamable-http"
			}
			out = append(out, Server{
				Name: name, Source: source, Command: s.Command,
				// Redacted here, not at the print or upload site: this is the
				// one place every consumer (terminal, --json, RegisterServer)
				// necessarily passes through, so there is no call site left
				// that could forget to do it.
				Args: redactArgs(s.Args), URL: redactURL(s.URL), Transport: transport,
			})
		}
	}
	return out
}
