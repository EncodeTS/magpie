package proc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookPathWhereAndFindToolWhere(t *testing.T) {
	dir1 := filepath.Join(t.TempDir(), "shim")
	dir2 := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(dir1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	shimBin := installTool(t, dir1, "mytool")
	realBin := installTool(t, dir2, "mytool")
	Forget()
	t.Cleanup(Forget)

	accept := func(p string) bool {
		return p != "" && !strings.HasPrefix(p, dir1)
	}

	// Only rejected dir1 on PATH -> LookPathWhere returns ErrNotFound.
	t.Setenv("PATH", dir1)
	Forget()
	if got, err := LookPathWhere("mytool", accept); !errors.Is(err, exec.ErrNotFound) || got != "" {
		t.Fatalf("only rejected on PATH: got (%q, %v), want (\"\", ErrNotFound)", got, err)
	}
	if got := FindToolWhere("mytool", accept); got != "" {
		t.Fatalf("FindToolWhere only rejected: got %q, want empty", got)
	}

	// Rejected dir1 before accepted dir2 -> skips dir1 and returns realBin in dir2.
	t.Setenv("PATH", dir1+string(os.PathListSeparator)+dir2)
	Forget()
	got, err := LookPathWhere("mytool", accept)
	if err != nil || got != realBin {
		t.Fatalf("LookPathWhere(%q) = (%q, %v), want (%q, nil) (shim=%q)", "mytool", got, err, realBin, shimBin)
	}
	if got := FindToolWhere("mytool", accept); got != realBin {
		t.Fatalf("FindToolWhere(%q) = %q, want %q", "mytool", got, realBin)
	}
}
