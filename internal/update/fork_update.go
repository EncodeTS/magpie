package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/yetone/magpie/internal/lazyre"
	"github.com/yetone/magpie/internal/source"
)

// Fork self-update configuration. Fork builds (-fork.* versions) never check
// usemagpie.ai or yetone/magpie-releases; they check GitHub Releases of
// forkReleaseRepo and verify both the fork's Ed25519 signature over SHA256SUMS
// and GitHub Actions SLSA build attestations for fork-build.yml.
const forkReleaseRepo = "EncodeTS/magpie"

var (
	forkCurrentVersion atomic.Pointer[string]

	// forkSigningKey is the base64-encoded 32-byte Ed25519 public key whose
	// private seed lives only as FORK_UPDATE_SIGNING_KEY in EncodeTS/magpie.
	forkSigningKey = "04CrVwLdSZKlLlZPgXZXy68TkpI9NMGbzYz6YJFs6ig="

	forkAttestRepo = forkReleaseRepo

	forkAttestID = struct{ SAN, Issuer, Repo string }{
		SAN:    `^https://github\.com/` + regexp.QuoteMeta(forkReleaseRepo) + `/\.github/workflows/fork-build\.yml@refs/(heads/fork/main|tags/fork-[0-9A-Za-z.+-]+)$`,
		Issuer: "https://token.actions.githubusercontent.com",
		Repo:   "https://github.com/" + forkReleaseRepo,
	}

	forkTagRe = lazyre.New(`^fork-v(\d+\.\d+\.\d+)-([0-9A-Za-z.-]+)$`)
)

// SetVersion records the running binary's build version so update checks know
// whether this binary is a fork build that updates from EncodeTS/magpie.
func SetVersion(v string) {
	s := strings.TrimSpace(v)
	forkCurrentVersion.Store(&s)
}

func runningVersion() string {
	if p := forkCurrentVersion.Load(); p != nil {
		return *p
	}
	return ""
}

func forkUpdateActive() bool {
	return IsFork(runningVersion())
}

func activeSigningKey() string {
	if forkUpdateActive() {
		return forkSigningKey
	}
	return signingKey
}

func activeAttestRepo() string {
	if forkUpdateActive() {
		return forkAttestRepo
	}
	return attestRepo
}

func activeAttestID() struct{ SAN, Issuer, Repo string } {
	if forkUpdateActive() {
		return forkAttestID
	}
	return attestID
}

// forkTagToVersion converts a fork release tag (such as "fork-v0.1.4777-3")
// into the semver string embedded in the binary ("0.1.4777-fork.3"). Non-fork
// tags are rejected.
func forkTagToVersion(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	var ver string
	if m := forkTagRe.FindStringSubmatch(tag); m != nil {
		if strings.HasPrefix(strings.ToLower(m[2]), "fork") {
			ver = m[1] + "-" + m[2]
		} else {
			ver = m[1] + "-fork." + m[2]
		}
	} else if strings.HasPrefix(tag, "fork-") {
		raw := strings.TrimPrefix(strings.TrimPrefix(tag, "fork-"), "v")
		if strings.Contains(strings.ToLower(raw), "-fork") {
			ver = raw
		} else {
			ver = raw + "-fork.1"
		}
	} else {
		ver = strings.TrimPrefix(tag, "v")
	}
	if !IsFork(ver) {
		return "", false
	}
	return ver, true
}

// forkVersionToTag maps a fork semver ("0.1.4777-fork.3") back to its GitHub
// release tag ("fork-v0.1.4777-3").
func forkVersionToTag(version string) string {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	base, pre, ok := strings.Cut(v, "-")
	if !ok || !isForkVersion(pre) {
		return "fork-v" + v
	}
	if suffix, cut := strings.CutPrefix(strings.ToLower(pre), "fork."); cut && suffix != "" {
		return "fork-v" + base + "-" + pre[len("fork."):]
	}
	return "fork-v" + base + "-" + pre
}

func forkReleasePage(version string) string {
	return fmt.Sprintf("%s/%s/releases/tag/%s", githubWeb, forkReleaseRepo, forkVersionToTag(version))
}

type ghReleaseItem struct {
	Tag        string `json:"tag_name"`
	Body       string `json:"body"`
	Page       string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func ghReleaseFiles(item ghReleaseItem) map[string]ghFile {
	files := map[string]ghFile{}
	for _, a := range item.Assets {
		if strings.HasPrefix(a.URL, githubAPI+"/") {
			files[a.Name] = ghFile{api: a.URL, size: a.Size}
		}
	}
	return files
}

func forkGithubLatest(ctx context.Context, lang string) (*Release, error) {
	tag, ver, notes, page, files, err := forkGithubTag(ctx)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s/%s/releases/download/%s/", githubWeb, forkReleaseRepo, tag)
	sums, err := githubFile(ctx, base+"SHA256SUMS", files["SHA256SUMS"].api)
	if err != nil {
		return nil, err
	}
	sig, err := githubFile(ctx, base+"SHA256SUMS.sig", files["SHA256SUMS.sig"].api)
	if err != nil {
		return nil, fmt.Errorf("%s has no signature: %w", tag, err)
	}
	rel := &Release{
		Version: ver,
		Notes:   InLang(notes, lang),
		URL:     page,
		Assets:  map[string]Asset{},
		Signed:  &Signed{Sums: sums, Sig: strings.TrimSpace(sig)},
	}
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		name := strings.TrimPrefix(f[1], "*")
		if name == "" || strings.ContainsAny(name, `/\`) || name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
			continue
		}
		u := base + url.PathEscape(name)
		rel.Assets[name] = Asset{URL: u, GitHub: u, API: files[name].api, Size: files[name].size}
	}
	if err := rel.verify(); err != nil {
		return nil, err
	}
	return rel, nil
}

func forkGithubTag(ctx context.Context) (tag, version, notes, page string, files map[string]ghFile, err error) {
	files = map[string]ghFile{}
	var apiErrs []error

	// 1. Try /releases/latest (normal fork releases).
	if req, rerr := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/repos/%s/releases/latest", githubAPI, forkReleaseRepo), nil); rerr == nil {
		req.Header.Set("Accept", "application/vnd.github+json")
		if res, derr := source.Do(client, req); derr == nil {
			var gh ghReleaseItem
			if res.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&gh) == nil && !gh.Draft {
				res.Body.Close()
				if ver, ok := forkTagToVersion(gh.Tag); ok {
					return gh.Tag, ver, gh.Body, gh.Page, ghReleaseFiles(gh), nil
				}
				apiErrs = append(apiErrs, fmt.Errorf("latest tag %q is not a fork release", gh.Tag))
			} else {
				res.Body.Close()
				apiErrs = append(apiErrs, fmt.Errorf("GitHub's API (/releases/latest): %s", res.Status))
			}
		} else {
			apiErrs = append(apiErrs, derr)
		}
	}

	// 2. Fall back to /releases list (covers prereleases or non-fork latest tag).
	if req, rerr := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/repos/%s/releases?per_page=20", githubAPI, forkReleaseRepo), nil); rerr == nil {
		req.Header.Set("Accept", "application/vnd.github+json")
		if res, derr := source.Do(client, req); derr == nil {
			var list []ghReleaseItem
			if res.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&list) == nil {
				res.Body.Close()
				var best *ghReleaseItem
				var bestVer string
				for i := range list {
					item := &list[i]
					if item.Draft {
						continue
					}
					ver, ok := forkTagToVersion(item.Tag)
					if !ok {
						continue
					}
					if best == nil || Newer(ver, bestVer) {
						best, bestVer = item, ver
					}
				}
				if best != nil {
					return best.Tag, bestVer, best.Body, best.Page, ghReleaseFiles(*best), nil
				}
				apiErrs = append(apiErrs, errors.New("no published fork releases found"))
			} else {
				res.Body.Close()
				apiErrs = append(apiErrs, fmt.Errorf("GitHub's API (/releases): %s", res.Status))
			}
		} else {
			apiErrs = append(apiErrs, derr)
		}
	}

	// 3. Rate-limit fallback: /releases/latest web redirect needs no API quota.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	pr, rerr := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/releases/latest", githubWeb, forkReleaseRepo), nil)
	if rerr != nil {
		err = errors.Join(append(apiErrs, rerr)...)
		return
	}
	pres, perr := source.Do(&c, pr)
	if perr != nil {
		err = fmt.Errorf("GitHub: %w", errors.Join(append(apiErrs, perr)...))
		return
	}
	defer pres.Body.Close()
	loc, _ := url.Parse(pres.Header.Get("Location"))
	if loc != nil {
		if i := strings.LastIndex(loc.Path, "/releases/tag/"); i >= 0 {
			tag = strings.Trim(loc.Path[i+len("/releases/tag/"):], "/")
		}
	}
	ver, ok := forkTagToVersion(tag)
	if !ok || strings.Contains(tag, "/") {
		tag = ""
		err = fmt.Errorf("GitHub's release page named no fork release (%s): %w", pres.Status, errors.Join(apiErrs...))
		return
	}
	return tag, ver, "", fmt.Sprintf("%s/%s/releases/tag/%s", githubWeb, forkReleaseRepo, tag), files, nil
}

func forkGithubNotes(ctx context.Context, lang string) ([]Note, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/repos/%s/releases?per_page=30", githubAPI, forkReleaseRepo), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := source.Do(client, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fork release notes: %s", res.Status)
	}
	var list []ghReleaseItem
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("fork release notes: %w", err)
	}
	var out []Note
	for _, item := range list {
		if item.Draft {
			continue
		}
		ver, ok := forkTagToVersion(item.Tag)
		if !ok {
			continue
		}
		out = append(out, Note{
			Version: ver,
			Notes:   InLang(item.Body, lang),
			URL:     item.Page,
		})
	}
	return out, nil
}
