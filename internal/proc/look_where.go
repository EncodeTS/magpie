package proc

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// LookPathWhere behaves like LookPath, except that when accept is non-nil it
// skips rejected binaries (such as an editor's copilot-shim) and continues
// searching subsequent entries on PATH.
func LookPathWhere(name string, accept func(string) bool) (string, error) {
	p, err := LookPath(name)
	if accept == nil {
		return p, err
	}
	if err == nil && accept(p) {
		return p, nil
	}
	if err != nil || strings.ContainsAny(name, `/\`) {
		if err == nil {
			err = &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return "", err
	}
	dirs := pathDirs()
	if hung := hungDirs(dirs); hung != nil {
		filtered := make([]string, 0, len(dirs))
		for _, d := range dirs {
			if !hung[d] {
				filtered = append(filtered, d)
			}
		}
		dirs = filtered
	}
	for _, d := range dirs {
		if d == "" || d == "." {
			continue
		}
		cand, lerr := execLookPath(filepath.Join(d, name))
		if lerr != nil {
			continue
		}
		cand = Unwrap(name, cand)
		if accept(cand) {
			return cand, nil
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// FindToolWhere behaves like FindTool, except that when accept is non-nil it
// skips rejected matches and checks all remaining locations from FindTools.
func FindToolWhere(name string, accept func(string) bool) string {
	if accept == nil {
		return FindTool(name)
	}
	if p := FindTool(name); p != "" && accept(p) {
		return p
	}
	for _, p := range FindTools(name) {
		if accept(p) {
			return p
		}
	}
	return ""
}
