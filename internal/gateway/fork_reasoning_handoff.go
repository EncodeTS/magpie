package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/yetone/magpie/internal/claudeseal"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/settings"
	"github.com/yetone/magpie/internal/steady"
)

const (
	sealIssuerLimit      = 4096
	sealIssuerTTL        = 14 * 24 * time.Hour
	sealIssuerRefreshGap = time.Hour
	sealObserverCap      = 8 << 20
)

type sealIssuerEntry struct {
	issuer string
	at     time.Time
}

type sealIssuersDiskEntry struct {
	Issuer string `json:"i"`
	AtUnix int64  `json:"t"`
}

type sealIssuersDisk struct {
	Version int                             `json:"v"`
	Entries map[string]sealIssuersDiskEntry `json:"entries"`
}

var sealIssuersPath = func() string {
	return filepath.Join(settings.Dir(), "fork-seal-issuers.json")
}

// Lock ordering: always acquire ioMu before mu, never mu before ioMu.
var sealIssuers = struct {
	mu         sync.Mutex
	ioMu       sync.Mutex
	loadedPath string
	gen        uint64
	savedGen   uint64
	m          map[[sha256.Size]byte]sealIssuerEntry
}{m: map[[sha256.Size]byte]sealIssuerEntry{}}

func loadSealIssuersFile(path string, now time.Time) map[[sha256.Size]byte]sealIssuerEntry {
	m := map[[sha256.Size]byte]sealIssuerEntry{}
	if path == "" {
		return m
	}
	raw, err := steady.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return m
	}
	var disk sealIssuersDisk
	if json.Unmarshal(raw, &disk) != nil || len(disk.Entries) == 0 {
		return m
	}
	type loadedItem struct {
		key [sha256.Size]byte
		ent sealIssuerEntry
	}
	items := make([]loadedItem, 0, len(disk.Entries))
	for hexKey, rec := range disk.Entries {
		if rec.Issuer == "" || rec.AtUnix <= 0 {
			continue
		}
		at := time.Unix(rec.AtUnix, 0)
		if now.Sub(at) > sealIssuerTTL {
			continue
		}
		b, err := hex.DecodeString(hexKey)
		if err != nil || len(b) != sha256.Size {
			continue
		}
		var key [sha256.Size]byte
		copy(key[:], b)
		items = append(items, loadedItem{key: key, ent: sealIssuerEntry{issuer: rec.Issuer, at: at}})
	}
	if len(items) > sealIssuerLimit {
		slices.SortFunc(items, func(a, b loadedItem) int {
			return b.ent.at.Compare(a.ent.at)
		})
		items = items[:sealIssuerLimit]
	}
	for _, it := range items {
		m[it.key] = it.ent
	}
	return m
}

func ensureSealIssuersLoaded(now time.Time) string {
	path := sealIssuersPath()
	sealIssuers.mu.Lock()
	if sealIssuers.loadedPath == path && sealIssuers.m != nil {
		sealIssuers.mu.Unlock()
		return path
	}
	sealIssuers.mu.Unlock()

	sealIssuers.ioMu.Lock()
	defer sealIssuers.ioMu.Unlock()

	sealIssuers.mu.Lock()
	if sealIssuers.loadedPath == path && sealIssuers.m != nil {
		sealIssuers.mu.Unlock()
		return path
	}
	sealIssuers.mu.Unlock()

	loaded := loadSealIssuersFile(path, now)

	sealIssuers.mu.Lock()
	if sealIssuers.loadedPath != path || sealIssuers.m == nil {
		sealIssuers.m = loaded
		sealIssuers.loadedPath = path
		sealIssuers.gen = 0
		sealIssuers.savedGen = 0
	}
	sealIssuers.mu.Unlock()
	return path
}

func persistSealIssuers(path string, want uint64, now time.Time) {
	if path == "" {
		return
	}
	sealIssuers.ioMu.Lock()
	defer sealIssuers.ioMu.Unlock()

	sealIssuers.mu.Lock()
	if sealIssuers.loadedPath != path || sealIssuers.savedGen >= want {
		sealIssuers.mu.Unlock()
		return
	}
	snapGen := sealIssuers.gen
	entries := make(map[string]sealIssuersDiskEntry, len(sealIssuers.m))
	for k, v := range sealIssuers.m {
		if now.Sub(v.at) > sealIssuerTTL {
			delete(sealIssuers.m, k)
			continue
		}
		entries[hex.EncodeToString(k[:])] = sealIssuersDiskEntry{
			Issuer: v.issuer,
			AtUnix: v.at.Unix(),
		}
	}
	sealIssuers.mu.Unlock()

	data, err := json.Marshal(sealIssuersDisk{Version: 1, Entries: entries})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if err := steady.WriteFile(path, data, 0o600); err != nil {
		return
	}
	sealIssuers.mu.Lock()
	if sealIssuers.loadedPath == path && snapGen > sealIssuers.savedGen {
		sealIssuers.savedGen = snapGen
	}
	sealIssuers.mu.Unlock()
}

func recordSealIssuer(enc, issuer string) {
	if enc == "" || issuer == "" || claudeseal.Is(enc) {
		return
	}
	sum := sha256.Sum256([]byte(enc))
	now := time.Now()
	path := ensureSealIssuersLoaded(now)

	sealIssuers.mu.Lock()
	if sealIssuers.m == nil {
		sealIssuers.m = map[[sha256.Size]byte]sealIssuerEntry{}
	}
	if prev, ok := sealIssuers.m[sum]; ok && prev.issuer == issuer && now.Sub(prev.at) < sealIssuerRefreshGap {
		sealIssuers.mu.Unlock()
		return
	}
	if _, ok := sealIssuers.m[sum]; !ok && len(sealIssuers.m) >= sealIssuerLimit {
		var oldestKey [sha256.Size]byte
		var oldestAt time.Time
		for k, v := range sealIssuers.m {
			if now.Sub(v.at) > sealIssuerTTL {
				delete(sealIssuers.m, k)
				continue
			}
			if oldestAt.IsZero() || v.at.Before(oldestAt) {
				oldestKey, oldestAt = k, v.at
			}
		}
		if len(sealIssuers.m) >= sealIssuerLimit && !oldestAt.IsZero() {
			delete(sealIssuers.m, oldestKey)
		}
	}
	sealIssuers.m[sum] = sealIssuerEntry{issuer: issuer, at: now}
	sealIssuers.gen++
	want := sealIssuers.gen
	sealIssuers.mu.Unlock()
	persistSealIssuers(path, want, now)
}

func sealIssuerOf(enc string) (string, bool) {
	if enc == "" || claudeseal.Is(enc) {
		return "", false
	}
	sum := sha256.Sum256([]byte(enc))
	now := time.Now()
	ensureSealIssuersLoaded(now)
	sealIssuers.mu.Lock()
	defer sealIssuers.mu.Unlock()
	e, ok := sealIssuers.m[sum]
	if !ok {
		return "", false
	}
	if now.Sub(e.at) > sealIssuerTTL {
		delete(sealIssuers.m, sum)
		return "", false
	}
	return e.issuer, true
}

func providerIssuer(p provider.Provider, model string) string {
	return candidate{p: p, model: model}.vendor()
}

func codexIssuer(on *provider.Provider, base, model string) string {
	if on != nil {
		return candidate{p: *on, model: model}.vendor()
	}
	if h := provider.HostOf(base); h != "" {
		return "codex-relay|" + h
	}
	return "codex-relay"
}

func copilotHandoffScope(c candidate) string {
	return c.vendor() + "|" + c.model
}

// sealObserver watches Responses upstream replies and records which issuer
// produced each reasoning encrypted_content digest so a later Copilot handoff
// (#7410) only strips foreign seals from known other issuers.
type sealObserver struct {
	issuer string
	sse    bool
	line   bytes.Buffer
	body   bytes.Buffer
	tooBig bool
}

func newSealObserver(proto provider.Protocol, contentType, issuer string) *sealObserver {
	if proto != provider.Responses || issuer == "" {
		return nil
	}
	sse := strings.Contains(strings.ToLower(contentType), "text/event-stream")
	return &sealObserver{issuer: issuer, sse: sse}
}

func (o *sealObserver) write(p []byte) {
	if o == nil || len(p) == 0 {
		return
	}
	if o.sse {
		for len(p) > 0 {
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				if o.line.Len()+len(p) <= sealObserverCap {
					o.line.Write(p)
				} else {
					o.line.Reset()
				}
				return
			}
			if o.line.Len() > 0 {
				if o.line.Len()+i <= sealObserverCap {
					o.line.Write(p[:i])
					o.scanSSELine(o.line.Bytes())
				}
				o.line.Reset()
			} else {
				o.scanSSELine(p[:i])
			}
			p = p[i+1:]
		}
		return
	}
	if o.tooBig {
		return
	}
	if o.body.Len()+len(p) > sealObserverCap {
		o.tooBig = true
		o.body.Reset()
		return
	}
	o.body.Write(p)
}

func (o *sealObserver) flush() {
	if o == nil {
		return
	}
	if o.sse {
		if o.line.Len() > 0 {
			o.scanSSELine(o.line.Bytes())
			o.line.Reset()
		}
		return
	}
	if !o.tooBig && o.body.Len() > 0 {
		b := o.body.Bytes()
		if bytes.Contains(b, []byte("encrypted_content")) && bytes.Contains(b, []byte("reasoning")) {
			o.scanOutputArray(gjson.GetBytes(b, "output"))
		}
	}
	o.body.Reset()
}

func (o *sealObserver) scanSSELine(line []byte) {
	line = bytes.TrimSpace(line)
	if !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	payload := bytes.TrimSpace(line[5:])
	if len(payload) == 0 || payload[0] != '{' ||
		!bytes.Contains(payload, []byte("encrypted_content")) ||
		!bytes.Contains(payload, []byte("reasoning")) {
		return
	}
	root := gjson.ParseBytes(payload)
	if it := root.Get("item"); it.IsObject() && it.Get("type").String() == "reasoning" {
		if enc := it.Get("encrypted_content").String(); enc != "" {
			recordSealIssuer(enc, o.issuer)
		}
	}
	o.scanOutputArray(root.Get("response.output"))
}

func (o *sealObserver) scanOutputArray(arr gjson.Result) {
	if !arr.IsArray() {
		return
	}
	arr.ForEach(func(_, it gjson.Result) bool {
		if it.Get("type").String() == "reasoning" {
			if enc := it.Get("encrypted_content").String(); enc != "" {
				recordSealIssuer(enc, o.issuer)
			}
		}
		return true
	})
}

func isRawEmptyInvalidBodyJSON(raw []byte) bool {
	if !json.Valid(raw) {
		return false
	}
	root := gjson.ParseBytes(raw)
	if !root.IsObject() {
		return false
	}
	if e := root.Get("error"); e.IsObject() {
		code := e.Get("code")
		msg := e.Get("message")
		return code.Type == gjson.String && code.String() == "invalid_request_body" &&
			msg.Exists() && msg.Type == gjson.String && msg.String() == ""
	}
	if root.Get("error").Exists() {
		return false
	}
	code := root.Get("code")
	msg := root.Get("message")
	return code.Type == gjson.String && code.String() == "invalid_request_body" &&
		msg.Exists() && msg.Type == gjson.String && msg.String() == ""
}

func isASCIIStatusWords(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ' ') {
			return false
		}
	}
	return true
}

func unwrapWrappedEmptyInvalidBody(msg string) bool {
	idx := strings.Index(msg, ": 400")
	if idx <= 0 {
		return false
	}
	after := msg[idx+len(": 400"):]
	brace := strings.IndexByte(after, '{')
	if brace < 2 {
		return false
	}
	between := after[:brace]
	trimmed := strings.TrimRight(between, " ")
	if !strings.HasSuffix(trimmed, ":") {
		return false
	}
	statusWords := strings.TrimSpace(strings.TrimSuffix(trimmed, ":"))
	if !isASCIIStatusWords(statusWords) {
		return false
	}
	return isRawEmptyInvalidBodyJSON([]byte(after[brace:]))
}

// isCopilotEmptyInvalidBody matches Copilot's silent HTTP 400 rejection of a
// foreign reasoning encrypted_content item: status 400 with code
// "invalid_request_body" and strictly empty message (raw or wrapped by
// writeKeptError / writeVendorError). Non-empty messages such as " " or
// "  bad" are rejected.
func isCopilotEmptyInvalidBody(status int, errBody []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	b := bytes.TrimSpace(errBody)
	if len(b) == 0 {
		return false
	}
	if isRawEmptyInvalidBodyJSON(b) {
		return true
	}
	if !json.Valid(b) {
		if i := bytes.IndexByte(b, '{'); i > 0 {
			prefix := bytes.TrimSpace(b[:i])
			if bytes.HasSuffix(prefix, []byte(":")) && !bytes.ContainsAny(prefix, "{}") {
				return isRawEmptyInvalidBodyJSON(b[i:])
			}
		}
		return false
	}
	root := gjson.ParseBytes(b)
	e := root.Get("error")
	if !e.IsObject() {
		return false
	}
	code := e.Get("code")
	msg := e.Get("message")
	if msg.Type != gjson.String {
		return false
	}
	keptShape := code.Type == gjson.String && code.String() == "invalid_request_body"
	flatWrappedShape := e.Get("type").String() == "invalid_request_error" && (code.Type == gjson.Null || !code.Exists())
	if !keptShape && !flatWrappedShape {
		return false
	}
	return unwrapWrappedEmptyInvalidBody(msg.String())
}

// withoutObservedForeignReasoning removes ONLY type == "reasoning" input items
// whose encrypted_content has a known observed issuer distinct from targetIssuer.
// Target-owned seals, unknown seals, compactions, messages, tool items, images,
// include, and prompt_cache_key stay byte-for-byte untouched.
func withoutObservedForeignReasoning(body []byte, targetIssuer string) ([]byte, [][sha256.Size]byte, bool) {
	return stripCopilotReasoningSeals(body, targetIssuer, false)
}

// withoutUnverifiedForeignReasoning is the stateless fallback after Copilot
// still rejects a request with empty invalid_request_body: it strips reasoning
// items whose encrypted_content is not known to belong to targetIssuer, while
// keeping target-owned seals, compactions, messages, tool items, and images.
func withoutUnverifiedForeignReasoning(body []byte, targetIssuer string) ([]byte, [][sha256.Size]byte, bool) {
	return stripCopilotReasoningSeals(body, targetIssuer, true)
}

func stripCopilotReasoningSeals(body []byte, targetIssuer string, dropUnknown bool) ([]byte, [][sha256.Size]byte, bool) {
	if targetIssuer == "" {
		return nil, nil, false
	}
	var q map[string]json.RawMessage
	if decodeJSONView(body, &q) != nil {
		return nil, nil, false
	}
	items, isList := inputList(q["input"])
	if !isList {
		return nil, nil, false
	}
	kept := make([]json.RawMessage, 0, len(items))
	var dropped [][sha256.Size]byte
	for _, it := range items {
		var t sealedItem
		if decodeJSONView(it, &t) == nil && t.Type == "reasoning" && t.Enc != "" {
			issuer, known := sealIssuerOf(t.Enc)
			if (known && issuer != targetIssuer) || (dropUnknown && !known) {
				dropped = append(dropped, sha256.Sum256([]byte(t.Enc)))
				continue
			}
		}
		kept = append(kept, it)
	}
	if len(dropped) == 0 {
		return nil, nil, false
	}
	q["input"], _ = json.Marshal(kept)
	out, err := marshalJSON(q)
	if err != nil {
		return nil, nil, false
	}
	return out, dropped, true
}

// nextCopilotHandoffBody advances Copilot's #7410 recovery in at most two
// stages: stage 0->1 strips only observed foreign seals; stage 1->2 (or 0->2
// when no observed foreign seal exists) falls back to stripping unobserved
// reasoning seals while keeping known target-owned seals intact.
func nextCopilotHandoffBody(body []byte, targetIssuer string, stage int) ([]byte, [][sha256.Size]byte, int, bool) {
	if stage < 1 {
		if b, dropped, ok := withoutObservedForeignReasoning(body, targetIssuer); ok {
			return b, dropped, 1, true
		}
	}
	if stage < 2 {
		if b, dropped, ok := withoutUnverifiedForeignReasoning(body, targetIssuer); ok {
			return b, dropped, 2, true
		}
	}
	return nil, nil, stage, false
}
