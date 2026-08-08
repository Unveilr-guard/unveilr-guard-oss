// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Command unveilr is the Local Shield CLI: scan a repository for AI-SDLC
// findings, discover/register/shield local MCP servers, and test policy
// decisions against the Unveilr SaaS.
//
// Repository scanning is the bare invocation — `unveilr <path>`, no verb —
// deliberately: it is the product's headline capability, not one governance
// action among several, and it existed as a tested engine
// (internal/scanner/detect) with no command reaching it before this file.
// `scan` was already taken by MCP server discovery, and stays that way; see
// cmdInspect in inspect.go for the repository-scanning entry point.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	mcpadapter "github.com/unveilr/unveilr-guard/internal/adapters/mcp"
	"github.com/unveilr/unveilr-guard/internal/cloud/client"
	"github.com/unveilr/unveilr-guard/internal/config"
	agentDiscovery "github.com/unveilr/unveilr-guard/internal/discovery/agent"
	mcpdiscovery "github.com/unveilr/unveilr-guard/internal/discovery/mcp"
	"github.com/unveilr/unveilr-guard/internal/version"
)

const usage = `unveilr — Local Shield CLI (v%s)

Usage:
  unveilr <path> [--json] [--fail-on tier]
                                         Scan a repository for AI-SDLC findings
                                         (secrets, injection, unsafe MCP config,
                                         PII). --fail-on: info|low|medium|high
                                         |critical|none (default critical).
  unveilr scan                          Discover local coding agents + MCP servers
  unveilr register [--all]              Register discovered servers with the SaaS
  unveilr proxy --server <id> -- CMD…   Shield a local stdio MCP server
  unveilr status                        Show config + SaaS connectivity
  unveilr policy test --server <id> --tool <name> [--args JSON] [--auth aal1|aal2]

Environment:
  UNVEILR_SAAS_URL    SaaS admin API base URL (default http://localhost:8080)
  UNVEILR_API_TOKEN   Tenant-bound bearer or service token (required online)

Note: ` + "`scan`" + ` (the subcommand) means MCP server discovery, not repository
scanning — that is the bare ` + "`unveilr <path>`" + ` invocation above.
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
		// No verb: `unveilr <path>` scans a repository for AI-SDLC findings —
		// the bare, unqualified invocation, because this is the product's
		// headline capability, not one governance action among several (see
		// the package doc comment). Only dispatched when the argument
		// actually resolves to something on disk, so a genuine typo of a
		// known subcommand still fails as "unknown command" rather than as a
		// confusing file-not-found.
		if _, err := os.Stat(os.Args[1]); err == nil {
			os.Exit(cmdInspect(os.Args[1], os.Args[2:]))
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func requireOnlineAuth(cfg config.Config) {
	if cfg.APIToken == "" {
		fmt.Fprintln(os.Stderr, "UNVEILR_API_TOKEN is required for online governance; Unveilr does not use tenant-spoofing development headers")
		os.Exit(1)
	}
}

// scanResult is the --json shape: agents and MCP servers together, matching
// the enterprise SDK's local_discovery() combination — the same two
// questions ("how many agents", "what MCP servers are configured") answered
// from the same command. This is a breaking change to the previous bare-array
// --json shape; pre-1.0 (see README's Status section), documented here rather
// than versioned, since nothing else in the tree parsed the old shape.
type scanResult struct {
	Agents     []agentDiscovery.Agent `json:"agents"`
	McpServers []mcpdiscovery.Server  `json:"mcpServers"`
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	agents := agentDiscovery.Detect()
	servers := mcpdiscovery.Scan()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(scanResult{Agents: agents, McpServers: servers})
		return
	}

	if len(agents) == 0 {
		fmt.Println("No locally-installed coding agents found.")
	} else {
		fmt.Printf("Discovered %d coding agent(s):\n", len(agents))
		for _, a := range agents {
			fmt.Printf("  • %-20s (%s)\n", a.Name, a.Evidence)
		}
	}
	fmt.Println()
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
		fmt.Fprintln(os.Stderr, "usage: unveilr proxy --server <id> -- <command> [args...]")
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
	fmt.Printf("Local    : %d agent(s), %d MCP server(s) discovered\n", len(agentDiscovery.Detect()), len(mcpdiscovery.Scan()))
}

func cmdPolicy(cfg config.Config, args []string) {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: unveilr policy test --server <id> --tool <name> [--args JSON] [--auth aal1|aal2]")
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
