// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.unveilr.ai/guard/internal/scanner/detect"
)

// unveilr <path> is the bare, unqualified invocation: no subcommand, because
// this — scanning a repository for AI-SDLC findings — is the product's
// headline capability, not one governance action among several. `unveilr
// scan` was already taken by MCP server discovery before this existed, and
// stays that way; see cmd/unveilr/main.go's package doc.
//
// Excludes mirror apps/api/unveilr_api/scanning/walk.py in the enterprise
// repo deliberately: scanning the same tree with either product should skip
// the same noise, not disagree about what counts as source.

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".venv": true, "venv": true, "__pycache__": true,
	".next": true, ".next-dev": true, ".nuxt": true, "target": true,
	".pnpm-store": true, ".mypy_cache": true, ".pytest_cache": true,
	"coverage": true, ".terraform": true,
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".ico": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true,
	".bz2": true, ".7z": true, ".mp4": true, ".mov": true, ".mp3": true,
	".wav": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".so": true, ".dylib": true, ".dll": true, ".exe": true, ".bin": true,
	".class": true, ".jar": true, ".wasm": true, ".pyc": true, ".lockb": true,
}

// maxFileBytes mirrors ScanContext's default in the enterprise scanner.
const maxFileBytes = 1_000_000

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

type fileFinding struct {
	detect.Finding
	File string `json:"file"`
}

type inspectResult struct {
	Path         string        `json:"path"`
	FilesScanned int           `json:"filesScanned"`
	Score        int           `json:"score"`
	Findings     []fileFinding `json:"findings"`
}

// cmdInspect is the CLI wrapper: parse flags, run the pure scan, print,
// return the process exit code. The scan itself lives in runInspectScan,
// which takes no flags and does no I/O beyond reading the target, so it can
// be tested directly against a real temp directory without capturing stdout.
func cmdInspect(target string, args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	failOn := fs.String("fail-on", "critical", "exit non-zero if a finding at or above this severity is found (info|low|medium|high|critical|none)")
	_ = fs.Parse(args)

	result, err := runInspectScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unveilr: %v\n", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	} else {
		printInspectHuman(result)
	}

	return inspectExitCode(result.Findings, *failOn)
}

// runInspectScan walks target (a file or a directory) and runs the offline
// detector over every scannable file it finds.
func runInspectScan(target string) (inspectResult, error) {
	info, err := os.Stat(target)
	if err != nil {
		return inspectResult{}, err
	}

	result := inspectResult{Path: target}
	maxScore := 0
	walkOne := func(p string) {
		data, err := readIfScannable(p)
		if err != nil || data == "" {
			return
		}
		result.FilesScanned++
		findings, score := detect.Scan(data)
		if score > maxScore {
			maxScore = score
		}
		rel, relErr := filepath.Rel(target, p)
		if relErr != nil {
			rel = p
		}
		for _, f := range findings {
			result.Findings = append(result.Findings, fileFinding{Finding: f, File: rel})
		}
	}

	if info.IsDir() {
		_ = filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry: skip it, do not abort the scan
			}
			if d.IsDir() {
				if p != target && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			walkOne(p)
			return nil
		})
	} else {
		walkOne(target)
	}
	result.Score = maxScore

	sort.SliceStable(result.Findings, func(i, j int) bool {
		ri, rj := severityRank[result.Findings[i].Severity], severityRank[result.Findings[j].Severity]
		if ri != rj {
			return ri > rj
		}
		return result.Findings[i].File < result.Findings[j].File
	})

	return result, nil
}

func readIfScannable(path string) (string, error) {
	if binaryExts[strings.ToLower(filepath.Ext(path))] {
		return "", nil
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 || fi.Size() > maxFileBytes {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// A null byte in the first 512 bytes is a cheap, standard binary sniff —
	// good enough to skip images/archives that slipped past the extension
	// list without decoding the whole file first.
	probe := data
	if len(probe) > 512 {
		probe = probe[:512]
	}
	for _, b := range probe {
		if b == 0 {
			return "", nil
		}
	}
	return string(data), nil
}

func printInspectHuman(r inspectResult) {
	if len(r.Findings) == 0 {
		fmt.Printf("No findings in %d file(s) scanned under %s.\n", r.FilesScanned, r.Path)
		return
	}
	fmt.Printf("%d finding(s) across %d file(s) scanned under %s (risk score %d/100):\n\n",
		len(r.Findings), r.FilesScanned, r.Path, r.Score)
	for _, f := range r.Findings {
		fmt.Printf("  %-8s %-8s %s\n", strings.ToUpper(f.Severity), f.Rule, f.Message)
		fmt.Printf("           %s\n\n", f.File)
	}
}

// inspectExitCode returns 1 when a finding at or above the requested severity
// exists — the CI-gating contract, so this is what a pipeline actually calls.
// "none" opts all the way out for a report-only run.
func inspectExitCode(findings []fileFinding, failOn string) int {
	if failOn == "none" {
		return 0
	}
	threshold, ok := severityRank[failOn]
	if !ok {
		fmt.Fprintf(os.Stderr, "unveilr: unknown --fail-on value %q\n", failOn)
		return 1
	}
	for _, f := range findings {
		if severityRank[f.Severity] >= threshold {
			return 1
		}
	}
	return 0
}
