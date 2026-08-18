// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package client talks to the Unveilr SaaS admin API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.unveilr.ai/guard/internal/config"
	mcpdiscovery "go.unveilr.ai/guard/internal/discovery/mcp"
)

type Client struct {
	cfg  config.Config
	http *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.cfg.SaaSURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s -> %d: %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Health checks SaaS connectivity.
func (c *Client) Health() error {
	return c.do(http.MethodGet, "/healthz", nil, nil)
}

// RegisterServer registers a discovered local server by discovery (remote URL)
// or manually (stdio command captured in description/endpoint).
func (c *Client) RegisterServer(s mcpdiscovery.Server) (string, error) {
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if s.URL != "" {
		err := c.do(http.MethodPost, "/v1/servers/discover",
			map[string]any{"endpoint": s.URL, "name": s.Name, "transport": s.Transport}, &created)
		return created.ID, err
	}
	endpoint := s.Command
	if len(s.Args) > 0 {
		endpoint += " " + fmt.Sprint(s.Args)
	}
	err := c.do(http.MethodPost, "/v1/servers", map[string]any{
		"name": s.Name, "endpoint": endpoint, "transport": "stdio",
		"deploymentMode": "local", "environment": "local", "riskTier": "high",
	}, &created)
	return created.ID, err
}

// SimResult is the gateway's policy-test result, surfaced via the API.
type SimResult struct {
	Authorization struct {
		Decision         string   `json:"decision"`
		Allowed          bool     `json:"allowed"`
		Reason           string   `json:"reason"`
		RedactPaths      []string `json:"redactPaths"`
		ApprovalRequired bool     `json:"approvalRequired"`
		StepUpRequired   bool     `json:"stepUpRequired"`
	} `json:"authorization"`
	Detection struct {
		RiskScore   int    `json:"riskScore"`
		MaxSeverity string `json:"maxSeverity"`
	} `json:"detection"`
}

// Simulate runs the gateway policy engine for a tool call (used by proxy + policy test).
func (c *Client) Simulate(serverID, tool string, args map[string]any, scopes, roles []string, authLevel string) (*SimResult, error) {
	var res SimResult
	err := c.do(http.MethodPost, "/v1/policies/simulate", map[string]any{
		"serverId": serverID, "toolName": tool, "arguments": args,
		"scopes": scopes, "roles": roles, "authLevel": authLevel,
	}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// SendEvent best-effort streams a local security event to the SaaS.
func (c *Client) SendEvent(event map[string]any) {
	_ = c.do(http.MethodPost, "/v1/ingest/events", event, nil)
}
