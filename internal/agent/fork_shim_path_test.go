package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/yetone/magpie/internal/proc"
)

func TestCopilotShimBeforeRealCLIOnPath(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	name := "copilot"
	if runtime.GOOS == "windows" {
		name += ".cmd"
		t.Setenv("PATHEXT", ".CMD")
	}

	install := filepath.Join(t.TempDir(), "Microsoft VS Code")
	writeAt(t, filepath.Join(install, "resources", "app", "product.json"), `{"nameShort":"Visual Studio Code"}`)
	shimDir := filepath.Join(install, "bin", "copilot-shim")
	writeAt(t, filepath.Join(shimDir, name), "vscode-copilot-launcher\n")
	if err := os.Chmod(filepath.Join(shimDir, name), 0o755); err != nil {
		t.Fatal(err)
	}

	realDir := t.TempDir()
	realBin := filepath.Join(realDir, name)
	writeAt(t, realBin, "#!/bin/sh\necho 1.0.112\n")
	if err := os.Chmod(realBin, 0o755); err != nil {
		t.Fatal(err)
	}

	// Put VS Code's shim BEFORE the real Copilot CLI on PATH (#6679).
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)
	proc.Forget()
	t.Cleanup(proc.Forget)

	a := copilot(home, cfg)
	if !a.Detected() {
		t.Fatal("Detected() = false when real Copilot CLI follows copilot-shim on PATH")
	}
	if bin, _ := a.cliBin(); bin != realBin {
		t.Fatalf("cliBin() = %q, want %q", bin, realBin)
	}
	if bin := a.BinPath(); bin != realBin {
		t.Fatalf("BinPath() = %q, want %q", bin, realBin)
	}

	// Remove realDir so only the shim remains -> must report not installed.
	t.Setenv("PATH", shimDir)
	proc.Forget()
	a = copilot(home, cfg)
	if a.Detected() {
		t.Fatal("Detected() = true when only copilot-shim is on PATH")
	}
	if bin, _ := a.cliBin(); bin != "" {
		t.Fatalf("cliBin() = %q, want empty when only shim exists", bin)
	}
	if bin := a.BinPath(); bin != "" {
		t.Fatalf("BinPath() = %q, want empty when only shim exists", bin)
	}
}
