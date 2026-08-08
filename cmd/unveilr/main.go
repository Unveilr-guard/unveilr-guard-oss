// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Command unveilr-shield is the Local Shield CLI: discover, register, and shield local
// MCP servers, and test policy decisions against the Unveilr SaaS.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	mcpadapter "github.com/unveilr/unveilr-guard/internal/adapters/mcp"
	"github.com/unveilr/unveilr-guard/internal/cloud/client"
	"github.com/unveilr/unveilr-guard/internal/config"
	mcpdiscovery "github.com/unveilr/unveilr-guard/internal/discovery/mcp"
	"github.com/unveilr/unveilr-guard/internal/version"
)

const usage = `unveilr-shield — Local Shield CLI (v%s)

Usage:
  unveilr-shield scan                          Discover locally-configured MCP servers
  unveilr-shield register [--all]              Register discovered servers with the SaaS
  unveilr-shield proxy --server <id> -- CMD…   Shield a local stdio MCP server
  unveilr-shield status                        Show config + SaaS connectivity
  unveilr-shield policy test --server <id> --tool <name> [--args JSON] [--auth aal1|aal2]

Environment:
  UNVEILR_SAAS_URL    SaaS admin API base URL (default http://localhost:8080)
  UNVEILR_API_TOKEN   Tenant-bound bearer or service token (required online)

Note: this is the Local Shield (govern local MCP servers). To scan a repository
for AI-SDLC findings, use the separate scanner CLI: ` + "`unveilr scan`" + `.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usage, version.Version)
		os.Exit(1)
	}
	cfg := config.Load()
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "register":
		requireOnlineAuth(cfg)
		cmdRegister(cfg, os.Args[2:])
	case "proxy":
		requireOnlineAuth(cfg)
		cmdProxy(cfg, os.Args[2:])
	case "status":
		cmdStatus(cfg)
	case "policy":
		requireOnlineAuth(cfg)
		cmdPolicy(cfg, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Printf(usage, version.Version)
	case "-v", "--version", "version":
		fmt.Println(version.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		switch os.Args[1] {
		case "login", "upload":
			fmt.Fprintln(os.Stderr, "hint: that command belongs to the Unveilr scanner CLI (`unveilr`), not the Local Shield.")
		}
		os.Exit(1)
	}
}

func requireOnlineAuth(cfg config.Config) {
	if cfg.APIToken == "" {
		fmt.Fprintln(os.Stderr, "UNVEILR_API_TOKEN is required for online governance; Unveilr does not use tenant-spoofing development headers")
		os.Exit(1)
	}
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	servers := mcpdiscovery.Scan()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(servers)
		return
	}
	if len(servers) == 0 {
		fmt.Println("No local MCP servers found in known config locations.")
		return
	}
	fmt.Printf("Discovered %d local MCP server(s):\n", len(servers))
	for _, s := range servers {
		target := s.URL
		if target == "" {
			target = s.Command
		}
		fmt.Printf("  • %-20s [%s] %s (%s)\n", s.Name, s.Transport, target, s.Source)
	}
}

func cmdRegister(cfg config.Config, args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	all := fs.Bool("all", false, "register all discovered servers")
	_ = fs.Parse(args)

	api := client.New(cfg)
	servers := mcpdiscovery.Scan()
	if len(servers) == 0 {
		fmt.Println("Nothing to register (no local MCP servers discovered).")
		return
	}
	if !*all {
		fmt.Println("Pass --all to register the discovered servers:")
		for _, s := range servers {
			fmt.Printf("  • %s\n", s.Name)
		}
		return
	}
	for _, s := range servers {
		id, err := api.RegisterServer(s)
		if err != nil {
			fmt.Printf("  ✗ %-20s %v\n", s.Name, err)
			continue
		}
		fmt.Printf("  ✓ %-20s registered as %s (state: discovered — approve in the console)\n", s.Name, id)
	}
}

func cmdProxy(cfg config.Config, args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	serverID := fs.String("server", "", "registered server id to enforce against")
	_ = fs.Parse(args)
	rest := fs.Args()
	if *serverID == "" || len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: unveilr-shield proxy --server <id> -- <command> [args...]")
		os.Exit(1)
	}
	p := mcpadapter.New(cfg, *serverID)
	if err := p.Run(rest[0], rest[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "[unveilr] proxy exited: %v\n", err)
		os.Exit(1)
	}
}

func cmdStatus(cfg config.Config) {
	api := client.New(cfg)
	fmt.Printf("SaaS URL : %s\n", cfg.SaaSURL)
	authMode := "not configured"
	if cfg.APIToken != "" {
		authMode = "bearer token"
	}
	fmt.Printf("Auth     : %s\n", authMode)
	fmt.Printf("FS allow : %v\n", cfg.FilesystemAllowlist)
	if err := api.Health(); err != nil {
		fmt.Printf("SaaS     : UNREACHABLE (%v)\n", err)
		return
	}
	fmt.Println("SaaS     : reachable ✓")
	fmt.Printf("Local    : %d MCP server(s) discovered\n", len(mcpdiscovery.Scan()))
}

func cmdPolicy(cfg config.Config, args []string) {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: unveilr-shield policy test --server <id> --tool <name> [--args JSON] [--auth aal1|aal2]")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("policy test", flag.ExitOnError)
	serverID := fs.String("server", "", "server id")
	tool := fs.String("tool", "", "tool name")
	argsJSON := fs.String("args", "{}", "tool arguments as JSON")
	auth := fs.String("auth", "aal1", "auth assurance level")
	_ = fs.Parse(args[1:])

	if *serverID == "" || *tool == "" {
		fmt.Fprintln(os.Stderr, "--server and --tool are required")
		os.Exit(1)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(*argsJSON), &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --args JSON: %v\n", err)
		os.Exit(1)
	}
	api := client.New(cfg)
	res, err := api.Simulate(*serverID, *tool, parsed, []string{"mcp:call"}, []string{"developer"}, *auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decision : %s\n", res.Authorization.Decision)
	fmt.Printf("Allowed  : %v\n", res.Authorization.Allowed)
	fmt.Printf("Risk     : %d (%s)\n", res.Detection.RiskScore, res.Detection.MaxSeverity)
	fmt.Printf("Reason   : %s\n", res.Authorization.Reason)
	if len(res.Authorization.RedactPaths) > 0 {
		fmt.Printf("Redact   : %v\n", res.Authorization.RedactPaths)
	}
}
