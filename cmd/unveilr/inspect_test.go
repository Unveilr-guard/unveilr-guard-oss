// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"

	"go.unveilr.ai/guard/internal/scanner/detect"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunInspectScanFindsARealSecretAndReportsItsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "config/settings.py", "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")
	write(t, dir, "README.md", "this repository does normal things\n")

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.FilesScanned != 2 {
		t.Fatalf("filesScanned = %d, want 2", result.FilesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %v, want exactly 1", result.Findings)
	}
	if result.Findings[0].File != filepath.Join("config", "settings.py") {
		t.Errorf("finding attributed to %q, want config/settings.py", result.Findings[0].File)
	}
	if result.Findings[0].Rule != "SEC-AWS" {
		t.Errorf("rule = %q, want SEC-AWS", result.Findings[0].Rule)
	}
	if result.Score == 0 {
		t.Error("expected a positive risk score")
	}
}

func TestRunInspectScanSkipsExcludedDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A real secret, but buried in node_modules — must not surface. A tool
	// that flags dependency internals on every scan gets ignored.
	write(t, dir, "node_modules/pkg/index.js", "const key = 'AKIAIOSFODNN7EXAMPLE'\n")
	write(t, dir, ".git/config", "AKIAIOSFODNN7EXAMPLE\n")

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected excluded dirs to produce no findings, got %v", result.Findings)
	}
	if result.FilesScanned != 0 {
		t.Errorf("filesScanned = %d, want 0 (both files are under excluded dirs)", result.FilesScanned)
	}
}

func TestRunInspectScanSkipsBinaryFilesByExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "logo.png", "AKIAIOSFODNN7EXAMPLE") // a real secret shape, wrong container

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.FilesScanned != 0 || len(result.Findings) != 0 {
		t.Fatalf("expected a .png to be skipped entirely, got scanned=%d findings=%v", result.FilesScanned, result.Findings)
	}
}

func TestRunInspectScanSkipsFilesWithNullBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "data.unknown")
	if err := os.WriteFile(p, []byte("AKIA\x00IOSFODNN7EXAMPLE"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.FilesScanned != 0 {
		t.Errorf("a file with a null byte must be treated as binary and skipped, got scanned=%d", result.FilesScanned)
	}
}

func TestRunInspectScanOnASingleFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(p, []byte("token ghp_abcdefghijklmnopqrstuvwxyz0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := runInspectScan(p)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.FilesScanned != 1 || len(result.Findings) != 1 {
		t.Fatalf("scanning a single file directly: scanned=%d findings=%v", result.FilesScanned, result.Findings)
	}
}

func TestRunInspectScanRejectsANonexistentPath(t *testing.T) {
	t.Parallel()
	if _, err := runInspectScan(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent path")
	}
}

func TestRunInspectScanIsQuietOnAnOrdinaryRepo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "src/index.ts", "export const add = (a: number, b: number) => a + b;\n")
	write(t, dir, "package.json", `{"name": "x", "version": "1.0.0"}`)

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("false positive on an ordinary repo: %v", result.Findings)
	}
}

func TestRunInspectScanFindingsAreSortedMostSevereFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// PII-EMAIL is low severity; SEC-AWS is critical. Written in the "wrong"
	// order on disk to prove the result is actually sorted, not incidental.
	write(t, dir, "a_low.txt", "contact us at security@example.com\n")
	write(t, dir, "z_critical.txt", "AKIAIOSFODNN7EXAMPLE\n")

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %v", result.Findings)
	}
	if result.Findings[0].Severity != "critical" {
		t.Errorf("first finding severity = %q, want critical (most severe first)", result.Findings[0].Severity)
	}
}

func TestInspectExitCode(t *testing.T) {
	t.Parallel()
	findings := []fileFinding{
		{Finding: detect.Finding{Category: "secret_leak", Severity: "high", Message: "x", Rule: "SEC-X"}, File: "a"},
	}
	cases := []struct {
		failOn string
		want   int
	}{
		{"critical", 0}, // a high finding must not trip a critical-only gate
		{"high", 1},
		{"medium", 1},
		{"none", 0},
	}
	for _, tc := range cases {
		if got := inspectExitCode(findings, tc.failOn); got != tc.want {
			t.Errorf("--fail-on=%s: exit=%d, want %d", tc.failOn, got, tc.want)
		}
	}
}

func TestInspectExitCodeRejectsAnUnknownSeverity(t *testing.T) {
	t.Parallel()
	if got := inspectExitCode(nil, "extremely-critical"); got != 1 {
		t.Errorf("an unrecognised --fail-on value must fail closed, got exit=%d", got)
	}
}

func TestRootDirectoryNamedLikeASkipDirIsStillScanned(t *testing.T) {
	t.Parallel()
	// A repo checked out into a directory literally called "build" (or any
	// name that happens to match an excluded subdirectory name) must not
	// have its ENTIRE scan skipped just because of what the root is named —
	// only genuine subdirectories are excluded.
	parent := t.TempDir()
	dir := filepath.Join(parent, "build")
	write(t, dir, "settings.py", "AKIAIOSFODNN7EXAMPLE\n")

	result, err := runInspectScan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.FilesScanned != 1 || len(result.Findings) != 1 {
		t.Fatalf("root directory named like a skip-dir was not scanned: scanned=%d findings=%v", result.FilesScanned, result.Findings)
	}
}
