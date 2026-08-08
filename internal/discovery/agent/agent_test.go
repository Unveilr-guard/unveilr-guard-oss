// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// isolatedHome points os.UserHomeDir() (via HOME/USERPROFILE) at an empty
// temp directory, so every test starts from a machine with nothing
// installed. Without this, every assertion passes for the wrong reason on
// a developer's real machine.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	envVar := "HOME"
	if runtime.GOOS == "windows" {
		envVar = "USERPROFILE"
	}
	t.Setenv(envVar, home)
	t.Setenv("PATH", "") // no binaries resolvable
	return home
}

func names(agents []Agent) []string {
	out := make([]string, len(agents))
	for i, a := range agents {
		out[i] = a.Name
	}
	return out
}

func TestDetectOnACleanMachineFindsNothing(t *testing.T) {
	isolatedHome(t)
	if got := Detect(); len(got) != 0 {
		t.Fatalf("expected no agents, got %v", got)
	}
}

func TestDetectFindsClaudeCodeByStateDir(t *testing.T) {
	home := isolatedHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := Detect()

	if len(got) != 1 || got[0].Name != "claude-code" {
		t.Fatalf("got %v, want exactly claude-code", got)
	}
}

func TestDetectFindsCursorByConfigDir(t *testing.T) {
	home := isolatedHome(t)
	if err := os.Mkdir(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := Detect()

	if len(got) != 1 || got[0].Name != "cursor" {
		t.Fatalf("got %v, want exactly cursor", got)
	}
}

func TestGenericEditorDirectoryIsNotAgentEvidence(t *testing.T) {
	// A bare .vscode directory alone is not Copilot — most VS Code users have
	// none of these tools. Overclaiming here would make every scan noisy.
	home := isolatedHome(t)
	if err := os.Mkdir(filepath.Join(home, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := Detect(); len(got) != 0 {
		t.Fatalf("expected no agents from a bare .vscode dir, got %v", got)
	}
}

func TestDetectFindsCopilotByVersionedExtensionDir(t *testing.T) {
	home := isolatedHome(t)
	ext := filepath.Join(home, ".vscode", "extensions", "github.copilot-1.234.0")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}

	got := Detect()

	if len(got) != 1 || got[0].Name != "github-copilot" {
		t.Fatalf("got %v, want exactly github-copilot", got)
	}
	if got[0].Evidence != "path:"+ext {
		t.Errorf("evidence = %q, want path:%s", got[0].Evidence, ext)
	}
}

func TestUnrelatedExtensionDoesNotTriggerCopilot(t *testing.T) {
	home := isolatedHome(t)
	ext := filepath.Join(home, ".vscode", "extensions", "esbenp.prettier-vscode-9.0.0")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := Detect(); len(got) != 0 {
		t.Fatalf("expected no agents, got %v", got)
	}
}

func TestMultipleAgentsAllReportedSorted(t *testing.T) {
	home := isolatedHome(t)
	for _, d := range []string{".claude", ".cursor"} {
		if err := os.Mkdir(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got := names(Detect())

	want := []string{"claude-code", "cursor"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v (sorted)", got, want)
	}
}

func TestEachAgentAppearsAtMostOnce(t *testing.T) {
	// claude-code has TWO independent checks (binary, state dir). Only the
	// state dir is available here (PATH is cleared), but both existing would
	// still need to collapse to one entry.
	home := isolatedHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := Detect()

	count := 0
	for _, a := range got {
		if a.Name == "claude-code" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("claude-code appeared %d times, want 1: %v", count, got)
	}
}

func TestDetectFindsClaudeDesktopByConfigFile(t *testing.T) {
	isolatedHome(t)
	p := claudeDesktopConfigPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := Detect()

	if len(got) != 1 || got[0].Name != "claude-desktop" {
		t.Fatalf("got %v, want exactly claude-desktop", got)
	}
}
