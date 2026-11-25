package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func useForkVersion(t *testing.T, v string) {
	t.Helper()
	old := runningVersion()
	SetVersion(v)
	t.Cleanup(func() { SetVersion(old) })
}

func TestForkTagVersionMapping(t *testing.T) {
	cases := []struct {
		tag  string
		want string
		ok   bool
	}{
		{"fork-v0.1.4777-3", "0.1.4777-fork.3", true},
		{"fork-v0.1.4777-fork.3", "0.1.4777-fork.3", true},
		{"v0.1.4777-fork.3", "0.1.4777-fork.3", true},
		{"v0.1.4777", "", false},
		{"not-a-tag", "", false},
	}
	for _, tc := range cases {
		got, ok := forkTagToVersion(tc.tag)
		if ok != tc.ok || got != tc.want {
			t.Errorf("forkTagToVersion(%q) = (%q, %v), want (%q, %v)", tc.tag, got, ok, tc.want, tc.ok)
		}
	}
	if !Newer("0.1.4777-fork.3", "0.1.4777-fork.2") {
		t.Fatal("0.1.4777-fork.3 must be newer than 0.1.4777-fork.2")
	}
	if !Newer("0.1.4778-fork.1", "0.1.4777-fork.9") {
		t.Fatal("0.1.4778-fork.1 must be newer than 0.1.4777-fork.9")
	}
	if got := forkVersionToTag("0.1.4777-fork.3"); got != "fork-v0.1.4777-3" {
		t.Errorf("forkVersionToTag = %q, want fork-v0.1.4777-3", got)
	}
}

func TestForkSelfUpdateUsesForkRepoAndKeyWithoutOfficialSite(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("MAGPIE_UPDATE_FEED", "")
	t.Setenv("MAGPIE_NOTES_FEED", "")
	useForkVersion(t, "0.1.4777-fork.2")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := forkSigningKey
	forkSigningKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { forkSigningKey = oldKey })

	siteHits := 0
	siteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siteHits++
		http.Error(w, "official site must not be called by fork build", http.StatusTeapot)
	}))
	t.Cleanup(siteSrv.Close)
	oldSite := siteFeed
	siteFeed = siteSrv.URL + "/api/latest"
	t.Cleanup(func() { siteFeed = oldSite })

	assetName := BinaryAsset()
	assetBody := []byte("fake-fork-binary-payload")
	sumHex := fmt.Sprintf("%x", sha256.Sum256(assetBody))
	sums := fmt.Sprintf("%s  %s\n", sumHex, assetName)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("magpie release 0.1.4777-fork.3\n"+sums)))

	tag := "fork-v0.1.4777-3"
	apiLatestStatus := http.StatusOK
	apiListStatus := http.StatusOK
	var attestPath string

	var ghSrv *httptest.Server
	ghSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dl := "/" + forkReleaseRepo + "/releases/download/" + tag + "/"
		switch r.URL.Path {
		case "/repos/" + forkReleaseRepo + "/releases/latest":
			if apiLatestStatus != http.StatusOK {
				http.Error(w, "status", apiLatestStatus)
				return
			}
			fmt.Fprintf(w, `{"tag_name":%q,"body":"Fork notes 3","html_url":"%s/%s/releases/tag/%s","assets":[{"name":%q,"url":"%s/repos/%s/releases/assets/10","size":%d},{"name":"SHA256SUMS","url":"%s/repos/%s/releases/assets/11","size":%d},{"name":"SHA256SUMS.sig","url":"%s/repos/%s/releases/assets/12","size":%d}]}`,
				tag, ghSrv.URL, forkReleaseRepo, tag,
				assetName, ghSrv.URL, forkReleaseRepo, len(assetBody),
				ghSrv.URL, forkReleaseRepo, len(sums),
				ghSrv.URL, forkReleaseRepo, len(sig))
		case "/repos/" + forkReleaseRepo + "/releases":
			if apiListStatus != http.StatusOK {
				http.Error(w, "status", apiListStatus)
				return
			}
			fmt.Fprintf(w, `[{"tag_name":"fork-v0.1.4777-2","body":"Fork notes 2","html_url":"%s/%s/releases/tag/fork-v0.1.4777-2","prerelease":true},{"tag_name":%q,"body":"Fork notes 3","html_url":"%s/%s/releases/tag/%s","prerelease":true}]`,
				ghSrv.URL, forkReleaseRepo, tag, ghSrv.URL, forkReleaseRepo, tag)
		case "/" + forkReleaseRepo + "/releases/latest":
			http.Redirect(w, r, "/"+forkReleaseRepo+"/releases/tag/"+tag, http.StatusFound)
		case dl + "SHA256SUMS":
			w.Write([]byte(sums))
		case dl + "SHA256SUMS.sig":
			w.Write([]byte(sig + "\n"))
		default:
			if strings.HasPrefix(r.URL.Path, "/repos/"+forkReleaseRepo+"/attestations/sha256:") {
				attestPath = r.URL.Path
				http.Error(w, "rate limited", http.StatusForbidden)
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ghSrv.Close)

	oldWeb, oldAPI, oldAttestAPI := githubWeb, githubAPI, attestAPI
	githubWeb, githubAPI, attestAPI = ghSrv.URL, ghSrv.URL, ghSrv.URL
	t.Cleanup(func() { githubWeb, githubAPI, attestAPI = oldWeb, oldAPI, oldAttestAPI })

	// 1. Normal /releases/latest path
	rel, err := Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest failed: %v", err)
	}
	if siteHits != 0 {
		t.Fatalf("official site hit %d times, want 0", siteHits)
	}
	if rel.Version != "0.1.4777-fork.3" {
		t.Fatalf("Version = %q, want 0.1.4777-fork.3", rel.Version)
	}
	a, ok := rel.Assets[assetName]
	if !ok || a.SHA256 != sumHex || !a.attest {
		t.Fatalf("asset = %+v (ok=%v), want sha=%s attest=true", a, ok, sumHex)
	}
	if err := blockOfficialInstall(rel); err != nil {
		t.Fatalf("fork release unexpectedly blocked: %v", err)
	}

	// Attestation API must query EncodeTS/magpie, not yetone/magpie-releases.
	if err := attestedFile(context.Background(), a, assetName); err != nil {
		t.Fatalf("attestedFile under API 403 should fall back to ed25519, got: %v", err)
	}
	if want := "/repos/" + forkReleaseRepo + "/attestations/sha256:" + sumHex; attestPath != want {
		t.Fatalf("attestPath = %q, want %q", attestPath, want)
	}

	// 2. Prerelease fallback (/releases/latest 404 -> /releases list)
	apiLatestStatus = http.StatusNotFound
	rel, err = LatestIn(context.Background(), "zh")
	if err != nil || rel.Version != "0.1.4777-fork.3" {
		t.Fatalf("prerelease fallback = (%+v, %v), want 0.1.4777-fork.3", rel, err)
	}

	// 3. API rate-limit fallback (both API routes 403 -> web /releases/latest redirect)
	apiLatestStatus = http.StatusForbidden
	apiListStatus = http.StatusForbidden
	rel, err = LatestEvery(context.Background(), "")
	if err != nil || rel.Version != "0.1.4777-fork.3" {
		t.Fatalf("redirect fallback = (%+v, %v), want 0.1.4777-fork.3", rel, err)
	}

	// 4. Notes and ReleasePage point to fork repo without hitting usemagpie.ai
	apiListStatus = http.StatusOK
	notes, err := NotesBetween(context.Background(), "0.1.4777-fork.2", "0.1.4777-fork.3", "")
	if err != nil || len(notes) != 1 || notes[0].Version != "0.1.4777-fork.3" {
		t.Fatalf("NotesBetween = (%+v, %v), want [0.1.4777-fork.3]", notes, err)
	}
	if page := ReleasePage("0.1.4777-fork.3"); !strings.HasSuffix(page, "/"+forkReleaseRepo+"/releases/tag/fork-v0.1.4777-3") {
		t.Fatalf("ReleasePage = %q", page)
	}
	if siteHits != 0 {
		t.Fatalf("official site hit %d times after all fork calls, want 0", siteHits)
	}

	// 5. Wrong signing key (including upstream key) must fail verification.
	forkSigningKey = signingKey
	apiLatestStatus = http.StatusOK
	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("fork release signed by wrong key must fail verification")
	}
}

func TestForkEmbeddedPublicKeyFormat(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(forkSigningKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("forkSigningKey invalid: len=%d err=%v", len(pub), err)
	}
	if forkSigningKey == signingKey {
		t.Fatal("forkSigningKey must not equal upstream signingKey")
	}
	// Also verify activeAttestID matches a real fork tag workflow ref.
	useForkVersion(t, "0.1.4777-fork.3")
	idSpec := activeAttestID()
	re := regexp.MustCompile(idSpec.SAN)
	if !re.MatchString("https://github.com/EncodeTS/magpie/.github/workflows/fork-build.yml@refs/tags/fork-v0.1.4777-3") {
		t.Fatalf("fork SAN regex %q did not match tag ref", idSpec.SAN)
	}
	if !re.MatchString("https://github.com/EncodeTS/magpie/.github/workflows/fork-build.yml@refs/heads/fork/main") {
		t.Fatalf("fork SAN regex %q did not match fork/main ref", idSpec.SAN)
	}
	if re.MatchString("https://github.com/yetone/magpie-releases/.github/workflows/release.yml@refs/tags/v0.1.4777") {
		t.Fatalf("fork SAN regex %q must not match upstream repo", idSpec.SAN)
	}
}
