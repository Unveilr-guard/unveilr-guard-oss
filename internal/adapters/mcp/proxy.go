// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package proxy wraps a local stdio MCP server, enforcing policy + detection
// on every tool call before forwarding, and scanning/redacting responses. It
// speaks newline-delimited JSON-RPC (the common MCP stdio framing).
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/unveilr/unveilr-guard/internal/cloud/client"
	"github.com/unveilr/unveilr-guard/internal/config"
	"github.com/unveilr/unveilr-guard/internal/scanner/detect"
)

type Proxy struct {
	cfg      config.Config
	api      *client.Client
	serverID string
	outMu    sync.Mutex
	out      *bufio.Writer
	saasUp   bool
}

func New(cfg config.Config, serverID string) *Proxy {
	api := client.New(cfg)
	return &Proxy{cfg: cfg, api: api, serverID: serverID, out: bufio.NewWriter(os.Stdout), saasUp: api.Health() == nil}
}

// Run spawns the child MCP server and proxies stdio with enforcement.
func (p *Proxy) Run(command string, args []string) error {
	cmd := exec.Command(command, args...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", command, err)
	}
	fmt.Fprintf(os.Stderr, "[unveilr] shielding %q (server=%s, saas=%v)\n", command, p.serverID, p.saasUp)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.clientToChild(os.Stdin, childIn) }()
	go func() { defer wg.Done(); p.childToClient(childOut) }()
	wg.Wait()
	return cmd.Wait()
}

func (p *Proxy) writeJSON(v any) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	b, _ := json.Marshal(v)
	p.out.Write(b)
	p.out.WriteByte('\n')
	p.out.Flush()
}

func (p *Proxy) writeLine(line []byte) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	p.out.Write(line)
	p.out.WriteByte('\n')
	p.out.Flush()
}

func (p *Proxy) clientToChild(r io.Reader, childIn io.WriteCloser) {
	defer childIn.Close() // closing child stdin lets it exit when the client disconnects
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		var msg map[string]any
		if json.Unmarshal(line, &msg) != nil {
			p.forward(childIn, line)
			continue
		}
		if msg["method"] == "tools/call" {
			if blocked, errResp := p.enforce(msg); blocked {
				p.writeJSON(errResp) // synthesize error to the client; do not forward
				continue
			}
		}
		p.forward(childIn, line)
	}
}

func (p *Proxy) forward(childIn io.Writer, line []byte) {
	childIn.Write(line)
	childIn.Write([]byte("\n"))
}

func (p *Proxy) childToClient(childOut io.Reader) {
	sc := bufio.NewScanner(childOut)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		var msg map[string]any
		if json.Unmarshal(line, &msg) != nil {
			p.writeLine(line)
			continue
		}
		// Scan + redact result text before it reaches the client/agent.
		if result, ok := msg["result"].(map[string]any); ok {
			text := flattenContent(result)
			findings, score := detect.Scan(text)
			if len(findings) > 0 {
				p.api.SendEvent(map[string]any{"type": "detection", "direction": "response", "serverId": p.serverID, "findings": findings, "riskScore": score})
				redactResult(result)
				b, _ := json.Marshal(msg)
				p.writeLine(b)
				continue
			}
		}
		p.writeLine(line)
	}
}

// enforce returns (blocked, errorResponse). Local safety checks run first, but
// an authoritative SaaS policy decision is mandatory: unavailable governance
// fails closed rather than silently degrading to local-only enforcement.
func (p *Proxy) enforce(msg map[string]any) (bool, map[string]any) {
	id := msg["id"]
	params, _ := msg["params"].(map[string]any)
	toolName, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}

	// Local filesystem allowlist (always enforced, even offline).
	if path, ok := args["path"].(string); ok && !p.pathAllowed(path) {
		return true, rpcError(id, -32002, fmt.Sprintf("blocked: path %q outside filesystem allowlist", path))
	}

	// Local detection backstop.
	findings, score := detect.Scan(flattenArgs(args))
	if score >= 80 {
		p.api.SendEvent(map[string]any{"type": "block", "serverId": p.serverID, "toolName": toolName, "reason": "local detection backstop", "findings": findings})
		return true, rpcError(id, -32002, "blocked: request risk too high (local detection)")
	}

	if !p.saasUp {
		return true, rpcError(id, -32005, "blocked: Unveilr control plane is unavailable")
	}
	res, err := p.api.Simulate(p.serverID, toolName, args, []string{"mcp:call"}, []string{"developer"}, "aal1")
	if err != nil {
		return true, rpcError(id, -32005, "blocked: authoritative policy decision unavailable")
	}
	d := res.Authorization.Decision
	p.api.SendEvent(map[string]any{"type": "policy_decision", "serverId": p.serverID, "toolName": toolName, "decision": d})
	switch d {
	case "deny":
		return true, rpcError(id, -32002, "blocked by policy: "+res.Authorization.Reason)
	case "require_approval":
		return true, rpcError(id, -32003, "approval required: "+res.Authorization.Reason)
	case "step_up":
		return true, rpcError(id, -32004, "step-up authentication required")
	}
	return false, nil
}

func (p *Proxy) pathAllowed(path string) bool {
	abs := path
	if !filepath.IsAbs(path) {
		abs = filepath.Clean(path)
	}
	for _, allowed := range p.cfg.FilesystemAllowlist {
		if strings.HasPrefix(abs, allowed) || strings.HasPrefix(path, allowed) {
			return true
		}
	}
	return false
}

func rpcError(id any, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
}

func flattenArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	return string(b)
}

func flattenContent(result map[string]any) string {
	content, ok := result["content"].([]any)
	if !ok {
		b, _ := json.Marshal(result)
		return string(b)
	}
	var sb strings.Builder
	for _, c := range content {
		if m, ok := c.(map[string]any); ok {
			if t, ok := m["text"].(string); ok {
				sb.WriteString(t)
				sb.WriteString("\n")
			}
		}
	}
	return sb.String()
}

var secretRe = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|\b\d{3}-\d{2}-\d{4}\b`)

func redactResult(result map[string]any) {
	content, ok := result["content"].([]any)
	if !ok {
		return
	}
	for _, c := range content {
		if m, ok := c.(map[string]any); ok {
			if t, ok := m["text"].(string); ok {
				m["text"] = secretRe.ReplaceAllString(t, "[REDACTED]")
			}
		}
	}
}
