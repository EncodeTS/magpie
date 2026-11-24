package update

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasedForkVersions(t *testing.T) {
	cases := map[string]bool{
		"0.1.4761":          true,
		"v0.1.4761":         true,
		"0.1.4761-fork":     false,
		"0.1.4761-fork.1":   false,
		"v0.1.4761-Fork.2":  false,
		"0.1.4761-alpha.1":  true,
		"0.1.4761-3-g123ab": false,
	}
	for v, want := range cases {
		if got := Released(v); got != want {
			t.Errorf("Released(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestBlockOfficialInstall(t *testing.T) {
	t.Setenv("MAGPIE_ALLOW_OFFICIAL_OVERWRITE", "")

	officialCases := []struct {
		name string
		rel  *Release
	}{
		{
			name: "site URL",
			rel:  &Release{Version: "0.1.4800", URL: "https://usemagpie.ai/releases/0.1.4800"},
		},
		{
			name: "site CDN asset URL",
			rel: &Release{
				Version: "0.1.4800",
				URL:     "https://example.invalid/rel",
				Assets: map[string]Asset{
					"a.zip": {URL: "https://dl.usemagpie.ai/0.1.4800/a.zip"},
				},
			},
		},
		{
			name: "yetone/magpie-releases web asset",
			rel: &Release{
				Version: "0.1.4800",
				Assets: map[string]Asset{
					"a.zip": {GitHub: "https://github.com/yetone/magpie-releases/releases/download/v0.1.4800/a.zip"},
				},
			},
		},
		{
			name: "yetone/magpie-releases API asset",
			rel: &Release{
				Version: "0.1.4800",
				Assets: map[string]Asset{
					"a.zip": {API: "https://api.github.com/repos/yetone/magpie-releases/releases/assets/123"},
				},
			},
		},
	}

	for _, tc := range officialCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := blockOfficialInstall(tc.rel); err == nil {
				t.Fatalf("expected official release %q to be blocked", tc.name)
			}
		})
	}

	allowedCases := []struct {
		name string
		rel  *Release
	}{
		{
			name: "local test server",
			rel: &Release{
				Version: "0.1.4800",
				URL:     "http://127.0.0.1:12345/release",
				Assets: map[string]Asset{
					"a.zip": {URL: "http://127.0.0.1:12345/a.zip"},
				},
			},
		},
		{
			name: "localhost test server",
			rel: &Release{
				Version: "0.1.4800",
				URL:     "http://localhost:8080/release",
				Assets: map[string]Asset{
					"a.zip": {URL: "http://localhost:8080/a.zip"},
				},
			},
		},
		{
			name: "custom fork repo",
			rel: &Release{
				Version: "0.1.4800-fork.1",
				URL:     "https://github.com/EncodeTS/magpie/releases/tag/v0.1.4800-fork.1",
				Assets: map[string]Asset{
					"a.zip": {URL: "https://github.com/EncodeTS/magpie/releases/download/v0.1.4800-fork.1/a.zip"},
				},
			},
		},
	}

	for _, tc := range allowedCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := blockOfficialInstall(tc.rel); err != nil {
				t.Fatalf("unexpected block for %q: %v", tc.name, err)
			}
		})
	}

	t.Run("env override", func(t *testing.T) {
		t.Setenv("MAGPIE_ALLOW_OFFICIAL_OVERWRITE", "1")
		if err := blockOfficialInstall(officialCases[0].rel); err != nil {
			t.Fatalf("expected MAGPIE_ALLOW_OFFICIAL_OVERWRITE=1 to allow: %v", err)
		}
	})
}

func TestStageAndStageBinaryBlockOfficialWithoutNetwork(t *testing.T) {
	t.Setenv("MAGPIE_ALLOW_OFFICIAL_OVERWRITE", "")

	rel := &Release{
		Version: "0.1.9999",
		URL:     "https://usemagpie.ai/releases/0.1.9999",
		Assets: map[string]Asset{
			AppAsset():    {URL: "https://github.com/yetone/magpie-releases/releases/download/v0.1.9999/" + AppAsset()},
			BinaryAsset(): {URL: "https://github.com/yetone/magpie-releases/releases/download/v0.1.9999/" + BinaryAsset()},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled context proves guard triggers before any network/asset work

	_, err := Stage(ctx, rel, filepath.Join(t.TempDir(), "magpie.app"))
	if err == nil || !strings.Contains(err.Error(), "custom fork build") {
		t.Fatalf("Stage error = %v, want fork guard error", err)
	}

	_, err = StageBinary(ctx, rel)
	if err == nil || !strings.Contains(err.Error(), "custom fork build") {
		t.Fatalf("StageBinary error = %v, want fork guard error", err)
	}
}
