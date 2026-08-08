// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package schema holds the externally-visible contracts: the shapes that cross
// process and organisation boundaries. They are versioned, and they are the
// only thing shared with the Unveilr enterprise plane — never code (ADR-002,
// ADR-007).
//
// Changing anything here is a compatibility event. The JSON tags are the wire
// format and must match schemas/*.schema.json exactly; a test asserts this.
package schema

// APIVersion is the schema group and version for every kind in this package.
const APIVersion = "guard.unveilr.ai/v1alpha1"

// Kinds.
const (
	KindActionIntent  = "ActionIntent"
	KindDecision      = "Decision"
	KindEvidenceEvent = "EvidenceEvent"
	KindFinding       = "Finding"
	KindPolicy        = "Policy"
)

// ActionIntent is an operation an agent is preparing to perform, normalised by
// an adapter before evaluation.
//
// Adapters observe different things — an MCP tool call, a shell command, a cloud
// API call — and all of them produce this one shape, so a policy is written once
// and a new adapter needs a normaliser rather than a policy-language change
// (ADR-004). No cloud provider is part of the generic structure.
type ActionIntent struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Timestamp  string `json:"timestamp"`

	Agent    Agent          `json:"agent"`
	Actor    *Actor         `json:"actor,omitempty"`
	Action   Action         `json:"action"`
	Resource *Resource      `json:"resource,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// Agent is the agent about to act.
type Agent struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
	// Version is reported by the agent itself. Attested, never measured.
	Version string `json:"version,omitempty"`
}

// Actor types. Unattended is a first-class value, not an omission: a scheduled
// agent genuinely has no human behind it, and that is a different claim from
// "nobody told us". Treating silence as autonomy would let an un-instrumented
// caller read as deliberately autonomous.
const (
	ActorHuman      = "human"
	ActorService    = "service"
	ActorCustomer   = "customer"
	ActorUnattended = "unattended"
)

// Actor is who the agent is acting for.
type Actor struct {
	Type              string `json:"type"`
	ID                string `json:"id,omitempty"`
	ClientApplication string `json:"clientApplication,omitempty"`
}

// Action types. An open vocabulary: these are the known values, not a closed
// enum, so adding an adapter does not require changing this package.
const (
	ActionMCPTool   = "mcp.tool"
	ActionShellExec = "shell.exec"
	ActionCloudAPI  = "cloud.api"
	ActionFSWrite   = "fs.write"
)

// Action is what is about to happen.
type Action struct {
	Type     string `json:"type"`
	Provider string `json:"provider,omitempty"`
	Name     string `json:"name"`
	// Arguments MUST be redacted before persistence. Never store raw secrets.
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Resource is what the action targets.
type Resource struct {
	Type        string   `json:"type,omitempty"`
	ID          string   `json:"id,omitempty"`
	DataClasses []string `json:"dataClasses,omitempty"`
}
