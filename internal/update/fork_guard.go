package update

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ForkBlockOfficial prevents this fork build from overwriting itself with an
// upstream release from usemagpie.ai or yetone/magpie-releases.
var ForkBlockOfficial = true

func isForkVersion(pre string) bool {
	return strings.Contains(strings.ToLower(pre), "fork")
}

// IsFork reports whether v is a semver string whose prerelease identifies a
// fork build (for example, "0.1.4777-fork.3").
func IsFork(v string) bool {
	s := parse(v)
	return s != nil && isForkVersion(s.pre)
}

func isOfficialUpstreamURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		low := strings.ToLower(raw)
		return strings.Contains(low, "usemagpie.ai") || strings.Contains(low, "yetone/magpie-releases")
	}
	host := strings.ToLower(u.Hostname())
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return false
	}
	if host == "usemagpie.ai" || strings.HasSuffix(host, ".usemagpie.ai") {
		return true
	}
	path := strings.ToLower(u.Path)
	return strings.Contains(path, "yetone/magpie-releases")
}

func isOfficialUpstreamRelease(rel *Release) bool {
	if rel == nil {
		return false
	}
	if isOfficialUpstreamURL(rel.URL) {
		return true
	}
	for _, a := range rel.Assets {
		if isOfficialUpstreamURL(a.URL) || isOfficialUpstreamURL(a.GitHub) || isOfficialUpstreamURL(a.API) {
			return true
		}
	}
	return false
}

func blockOfficialInstall(rel *Release) error {
	if !ForkBlockOfficial || os.Getenv("MAGPIE_ALLOW_OFFICIAL_OVERWRITE") == "1" {
		return nil
	}
	if isOfficialUpstreamRelease(rel) {
		return fmt.Errorf("refusing to overwrite custom fork build with official upstream release %q (set MAGPIE_ALLOW_OFFICIAL_OVERWRITE=1 to override)", rel.Version)
	}
	return nil
}
