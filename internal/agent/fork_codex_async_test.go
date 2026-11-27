package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForkStoreAppPackageSelectsNewestMain(t *testing.T) {
	pkgs := []string{
		"OpenAI.Codex_26.1010.100.0_x64__2p2nqsd0c76g0",
		"OpenAI.Codex_26.1120.6357.0_x64__2p2nqsd0c76g0",
		"OpenAI.Codex_26.9999.0.0_neutral_split.scale-125_2p2nqsd0c76g0",
	}
	pkg, ver := storeAppPackage(pkgs, "OpenAI.Codex", "2p2nqsd0c76g0")
	if pkg != "OpenAI.Codex_26.1120.6357.0_x64__2p2nqsd0c76g0" || ver != "26.1120.6357.0" {
		t.Fatalf("got (%q, %q)", pkg, ver)
	}
}

func TestForkWindowsStoreCodexVersionUnblocksAsyncTable(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "app", "resources", "codex.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}

	wasRoot, wasRun := windowsStorePackageRoot, runVersion
	versions = memo{}
	t.Cleanup(func() {
		windowsStorePackageRoot, runVersion = wasRoot, wasRun
		versions = memo{}
	})

	const pkg = "OpenAI.Codex_26.1120.6357.0_x64__2p2nqsd0c76g0"
	windowsStorePackageRoot = func(p string) string {
		if p == pkg {
			return root
		}
		return ""
	}
	runVersion = func(b string) string {
		if b != bin {
			t.Errorf("runVersion(%q), want %q", b, bin)
		}
		return "codex-cli 0.171.0-alpha.13.2"
	}

	got := windowsStoreCodexVersion(pkg)
	if got != "0.171.0-alpha.13.2" {
		t.Fatalf("windowsStoreCodexVersion = %q, want 0.171.0-alpha.13.2", got)
	}
	if held := codexAsyncBlocked([]CodexReader{{Kind: "cli", Version: "0.170.0"}, {Kind: "app", Version: got}}); len(held) != 0 {
		t.Fatalf("expected async table unblocked, held=%+v", held)
	}

	// Missing PackageRootFolder stays empty and continues blocking safely.
	if miss := windowsStoreCodexVersion("OpenAI.Codex_missing"); miss != "" {
		t.Fatalf("expected empty version for missing package, got %q", miss)
	}
}
