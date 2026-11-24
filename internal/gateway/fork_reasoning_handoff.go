package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/yetone/magpie/internal/claudeseal"
	"github.com/yetone/magpie/internal/provider"
)

const (
	sealIssuerLimit = 4096
	sealIssuerTTL   = 12 * time.Hour
	sealObserverCap = 8 << 20
)

type sealIssuerEntry struct {
	issuer string
	at     time.Time
}

var sealIssuers = struct {
	mu sync.Mutex
	m  map[[sha256.Size]byte]sealIssuerEntry
}{m: map[[sha256.Size]byte]sealIssuerEntry{}}

func recordSealIssuer(enc, issuer string) {
	if enc == "" || issuer == "" || claudeseal.Is(enc) {
		return
	}
	sum := sha256.Sum256([]byte(enc))
	now := time.Now()
	sealIssuers.mu.Lock()
	defer sealIssuers.mu.Unlock()
	if sealIssuers.m == nil {
		sealIssuers.m = map[[sha256.Size]byte]sealIssuerEntry{}
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
}

func sealIssuerOf(enc string) (string, bool) {
	if enc == "" || claudeseal.Is(enc) {
		return "", false
	}
	sum := sha256.Sum256([]byte(enc))
	now := time.Now()
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
			if issuer, known := sealIssuerOf(t.Enc); known && issuer != targetIssuer {
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
