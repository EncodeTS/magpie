package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/yetone/magpie/internal/provider"
)

func TestForkForVendorDropsOtherInputItems(t *testing.T) {
	p := provider.Provider{ID: "copilot", Name: "Copilot"}
	in := []byte(`{"model":"gpt-6.1-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"other"},{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"enc1"},{"type":"other","extra":1},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}`)
	got := forVendor(p, in, false)
	if strings.Contains(string(got), `"other"`) {
		t.Fatalf("expected type=other items to be stripped: %s", got)
	}
	items := gjson.GetBytes(got, "input").Array()
	if len(items) != 3 {
		t.Fatalf("expected 3 remaining items, got %d: %s", len(items), got)
	}
	if items[0].Get("type").String() != "message" || items[1].Get("type").String() != "reasoning" || items[2].Get("type").String() != "message" {
		t.Fatalf("unexpected item order: %s", got)
	}

	// Requests without type=other stay byte-for-byte untouched even if text mentions "other".
	clean := []byte(`{"model":"gpt-6.1-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"some other word"}]}]}`)
	if gotClean := forVendor(p, clean, false); string(gotClean) != string(clean) {
		t.Fatalf("clean request changed:\n got %s\nwant %s", gotClean, clean)
	}
}

func TestForkInputKindWordsMatchesCopilotEnumRefusal(t *testing.T) {
	wantMatch := []string{
		`Copilot: Invalid value: 'other'. Supported values are: 'additional_tools', 'message', 'reasoning'.`,
		`{"error":{"message":"Invalid value: 'legacy_item'. Supported values are: 'compaction', 'message', 'reasoning'."}}`,
		`unsupported input item type`,
		`unknown item type: foo`,
	}
	for _, s := range wantMatch {
		if !inputKindWords.MatchString(s) {
			t.Errorf("expected inputKindWords match for %q", s)
		}
	}
	wantNoMatch := []string{
		`Invalid value: 'ultra'. Supported values are: 'low', 'medium', 'high'.`,
		`Invalid value for reasoning.effort`,
		`context_length_exceeded`,
	}
	for _, s := range wantNoMatch {
		if inputKindWords.MatchString(s) {
			t.Errorf("expected no inputKindWords match for %q", s)
		}
	}
}

func TestForkSamplingDeprecatedStripsAndRetriesResponses(t *testing.T) {
	for _, msg := range []string{
		"Unsupported parameter: 'temperature' is not supported with this model.",
		"Unsupported parameter: 'top_p' is not supported with this model.",
		"`temperature` is deprecated for this model.",
	} {
		if !samplingDeprecated.MatchString(msg) {
			t.Errorf("expected samplingDeprecated match for %q", msg)
		}
	}
	if samplingDeprecated.MatchString("Invalid value for 'temperature': must be between 0 and 2") {
		t.Errorf("should not match range validation error")
	}

	fresh(t)
	var mu sync.Mutex
	var bodies [][]byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if gjson.GetBytes(b, "temperature").Exists() || gjson.GetBytes(b, "top_p").Exists() {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"code":"invalid_request_body","message":"Unsupported parameter: 'temperature' is not supported with this model."}}`)
			return
		}
		if gjson.GetBytes(b, "stream").Bool() {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, sse(
				`data: {"type":"response.created","response":{"id":"resp_ok","status":"in_progress"}}`,
				`data: {"type":"response.output_text.delta","delta":"OK_NO_TEMP"}`,
				`data: {"type":"response.completed","response":{"id":"resp_ok","status":"completed","output":[{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"OK_NO_TEMP"}]}],"usage":{"input_tokens":5,"output_tokens":3}}}`,
			))
			return
		}
		io.WriteString(w, `{"id":"resp_ok","object":"response","status":"completed","output":[{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"OK_NO_TEMP"}]}],"usage":{"input_tokens":5,"output_tokens":3}}`)
	}))
	t.Cleanup(up.Close)

	if err := provider.Save(provider.Provider{
		ID:        "r1",
		Name:      "Responses One",
		Key:       "k-r1",
		Models:    []string{"gpt-6.1-sol"},
		Responses: up.URL + "/v1",
	}); err != nil {
		t.Fatal(err)
	}
	s := New()

	// 1. Translated path: /v1/chat/completions -> /v1/responses with temperature: 0.
	code, out := gatewayPost(t, s, "/v1/chat/completions", `{"model":"r1/gpt-6.1-sol","temperature":0,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 || !strings.Contains(out, "OK_NO_TEMP") {
		t.Fatalf("translated chat->responses retry failed: %d %s", code, out)
	}
	mu.Lock()
	gotTranslated := append([][]byte(nil), bodies...)
	bodies = nil
	mu.Unlock()
	if len(gotTranslated) != 2 {
		t.Fatalf("expected 2 upstream attempts (with temp -> without temp), got %d", len(gotTranslated))
	}
	if !gjson.GetBytes(gotTranslated[0], "temperature").Exists() || gjson.GetBytes(gotTranslated[1], "temperature").Exists() {
		t.Fatalf("unexpected temperature presence: first=%s second=%s", gotTranslated[0], gotTranslated[1])
	}

	// 2. Direct passthrough path: /v1/responses -> /v1/responses with temperature: 0.
	code2, out2 := gatewayPost(t, s, "/v1/responses", `{"model":"r1/gpt-6.1-sol","temperature":0,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
	if code2 != 200 || !strings.Contains(out2, "OK_NO_TEMP") {
		t.Fatalf("direct responses retry failed: %d %s", code2, out2)
	}
	mu.Lock()
	gotDirect := append([][]byte(nil), bodies...)
	mu.Unlock()
	if len(gotDirect) != 2 {
		t.Fatalf("expected 2 upstream attempts on direct path, got %d", len(gotDirect))
	}
	if !gjson.GetBytes(gotDirect[0], "temperature").Exists() || gjson.GetBytes(gotDirect[1], "temperature").Exists() {
		t.Fatalf("unexpected direct temperature presence: first=%s second=%s", gotDirect[0], gotDirect[1])
	}
}
