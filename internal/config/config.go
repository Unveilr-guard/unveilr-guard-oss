// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads Local Shield settings from the environment and an
// optional ~/.unveilr/config.json file.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	SaaSURL  string `json:"saasUrl"`
	APIToken string `json:"apiToken"`
	// FilesystemAllowlist restricts filesystem-tool path arguments locally.
	FilesystemAllowlist []string `json:"filesystemAllowlist"`
}

func defaults() Config {
	return Config{
		SaaSURL:             "http://localhost:8080",
		FilesystemAllowlist: []string{"/workspace", "/tmp", "./"},
	}
}

// Load merges defaults <- config file <- environment variables.
func Load() Config {
	c := defaults()

	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".unveilr", "config.json")
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &c)
		}
	}

	if v := os.Getenv("UNVEILR_SAAS_URL"); v != "" {
		c.SaaSURL = v
	}
	if v := os.Getenv("UNVEILR_API_TOKEN"); v != "" {
		c.APIToken = v
	}
	return c
}

// AuthHeaders returns the tenant-bound bearer token for control-plane calls.
func (c Config) AuthHeaders() map[string]string {
	if c.APIToken != "" {
		return map[string]string{"Authorization": "Bearer " + c.APIToken}
	}
	return map[string]string{}
}
