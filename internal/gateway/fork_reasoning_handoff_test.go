package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/claudeseal"
	"github.com/yetone/magpie/internal/provider"
)

func resetSealIssuersForTest() {
	sealIssuers.ioMu.Lock()
	sealIssuers.mu.Lock()
	sealIssuers.m = map[[sha256.Size]byte]sealIssuerEntry{}
	sealIssuers.loadedPath = ""
	sealIssuers.gen = 0
	sealIssuers.savedGen = 0
	sealIssuers.mu.Unlock()
	if path := sealIssuersPath(); path != "" {
		_ = os.Remove(path)
	}
	sealIssuers.ioMu.Unlock()
}

func clearSealIssuersMemoryForRestart() {
	sealIssuers.ioMu.Lock()
	sealIssuers.mu.Lock()
	sealIssuers.m = map[[sha256.Size]byte]sealIssuerEntry{}
	sealIssuers.loadedPath = ""
	sealIssuers.gen = 0
	sealIssuers.savedGen = 0
	sealIssuers.mu.Unlock()
	sealIssuers.ioMu.Unlock()
	refusedSeals.Lock()
	refusedSeals.m = map[string]sealsRefused{}
	refusedSeals.Unlock()
}

func TestForkClaudeSealShellDropped(t *testing.T) {
	think := claudeThinking("secret claude chain of thought", "sig_claude_1")
	redacted := claudeseal.Seal([]byte(`{"type":"redacted_thinking","data":"r"}`))
	in := `{"model":"gpt-6.2-sol","store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"k-shell","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},` +
		`{"type":"reasoning","id":"rs_c1","summary":[{"type":"summary_text","text":"secret claude chain of thought"}],"content":[{"type":"reasoning_text","text":"secret claude chain of thought"}],"encrypted_content":"` + think + `"},` +
		`{"type":"reasoning","id":"rs_c2","summary":[],"encrypted_content":"` + redacted + `"},` +
		`{"type":"function_call","call_id":"call_1","name":"shell","arguments":"{}"},` +
		`{"type":"function_call_output","call_id":"call_1","output":"ok"},` +
		`{"type":"reasoning","id":"rs_openai","summary":[],"encrypted_content":"gAAAA-openai-seal"}` +
		`]}`

	out := withoutClaudeSeals([]byte(in))
	s := string(out)
	if strings.Contains(s, claudeseal.Mark) || strings.Contains(s, "rs_c1") || strings.Contains(s, "rs_c2") || strings.Contains(s, "secret claude chain of thought") {
		t.Fatalf("Claude-sealed reasoning shell leaked into output: %s", s)
	}
	for _, want := range []string{`"gAAAA-openai-seal"`, `"call_1"`, `"k-shell"`, `"reasoning.encrypted_content"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %s to be preserved: %s", want, s)
		}
	}
	var parsed struct {
		Input []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	var reasoningIDs []string
	for _, it := range parsed.Input {
		if it.Type == "reasoning" {
			reasoningIDs = append(reasoningIDs, it.ID)
		}
	}
	if len(reasoningIDs) != 1 || reasoningIDs[0] != "rs_openai" {
		t.Fatalf("reasoning items = %v, want [rs_openai]", reasoningIDs)
	}
}

func TestForkIsCopilotEmptyInvalidBody(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"raw nested", 400, `{"error":{"code":"invalid_request_body","message":""}}`, true},
		{"raw flat", 400, `{"code":"invalid_request_body","message":""}`, true},
		{"provider prefixed raw", 400, `Copilot: {"error":{"code":"invalid_request_body","message":""}}`, true},
		{"kept error wrapped", 400, `{"error":{"message":"Copilot: 400 Bad Request: {\"error\":{\"message\":\"\",\"code\":\"invalid_request_body\"}}","code":"invalid_request_body"}}`, true},
		{"vendor error wrapped flat", 400, `{"error":{"message":"Copilot: 400 Bad Request: {\"code\":\"invalid_request_body\",\"message\":\"\"}","type":"invalid_request_error","code":null,"param":null}}`, true},
		{"kept status 400 no reason phrase", 400, `{"error":{"message":"Copilot: 400: {\"error\":{\"message\":\"\",\"code\":\"invalid_request_body\"}}","code":"invalid_request_body"}}`, true},
		{"single space message raw", 400, `{"error":{"code":"invalid_request_body","message":" "}}`, false},
		{"leading spaces message raw", 400, `{"error":{"code":"invalid_request_body","message":"  bad"}}`, false},
		{"kept wrapped single space", 400, `{"error":{"message":"Copilot:  ","code":"invalid_request_body"}}`, false},
		{"kept wrapped leading spaces bad", 400, `{"error":{"message":"Copilot:   bad","code":"invalid_request_body"}}`, false},
		{"non-empty invalid_request_body", 400, `{"error":{"code":"invalid_request_body","message":"bad field model"}}`, false},
		{"other code empty message", 400, `{"error":{"code":"model_not_supported","message":""}}`, false},
		{"wrong status 401", 401, `{"error":{"code":"invalid_request_body","message":""}}`, false},
		{"wrong status 500", 500, `{"error":{"code":"invalid_request_body","message":""}}`, false},
		{"html 400", 400, `<html><body>Bad Request</body></html>`, false},
		{"empty body", 400, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCopilotEmptyInvalidBody(tc.status, []byte(tc.body)); got != tc.want {
				t.Fatalf("isCopilotEmptyInvalidBody(%d, %s) = %v, want %v", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

func TestForkWithoutObservedForeignReasoning(t *testing.T) {
	resetSealIssuersForTest()
	target := "copilot|alice"
	foreign := "codex-relay|chatgpt.com"

	recordSealIssuer("gAAAA-own-seal", target)
	recordSealIssuer("gAAAA-foreign-seal", foreign)

	// Confirm sealIssuers stores only SHA-256 digests, not plaintext seals.
	sealIssuers.mu.Lock()
	if _, ok := sealIssuers.m[sha256.Sum256([]byte("gAAAA-foreign-seal"))]; !ok || len(sealIssuers.m) != 2 {
		sealIssuers.mu.Unlock()
		t.Fatalf("unexpected sealIssuers state: %+v", sealIssuers.m)
	}
	sealIssuers.mu.Unlock()

	body := `{
		"model":"gpt-6.2-sol",
		"stream":true,
		"include":["reasoning.encrypted_content"],
		"prompt_cache_key":"cache-handoff-1",
		"tools":[{"type":"function","name":"shell"}],
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"look"},{"type":"input_image","image_url":"data:image/png;base64,iVBOR"}]},
			{"type":"reasoning","id":"rs_foreign","summary":[{"type":"summary_text","text":"codex"}],"encrypted_content":"gAAAA-foreign-seal"},
			{"type":"reasoning","id":"rs_own","summary":[{"type":"summary_text","text":"copilot"}],"encrypted_content":"gAAAA-own-seal"},
			{"type":"reasoning","id":"rs_unknown","summary":[{"type":"summary_text","text":"unobserved"}],"encrypted_content":"gAAAA-unknown-seal"},
			{"type":"compaction","id":"cmp_1","encrypted_content":"gAAAA-foreign-seal"},
			{"type":"function_call","id":"fc_1","call_id":"call_9","name":"shell","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_9","output":"done"}
		]
	}`

	out, dropped, ok := withoutObservedForeignReasoning([]byte(body), target)
	if !ok {
		t.Fatal("expected foreign reasoning item to be stripped")
	}
	if len(dropped) != 1 || dropped[0] != sha256.Sum256([]byte("gAAAA-foreign-seal")) {
		t.Fatalf("dropped digests = %v", dropped)
	}
	s := string(out)
	if strings.Contains(s, `"rs_foreign"`) {
		t.Fatalf("foreign reasoning item remained: %s", s)
	}
	for _, want := range []string{
		`"rs_own"`,
		`"gAAAA-own-seal"`,
		`"rs_unknown"`,
		`"gAAAA-unknown-seal"`,
		`"cmp_1"`,
		`"data:image/png;base64,iVBOR"`,
		`"call_9"`,
		`"reasoning.encrypted_content"`,
		`"cache-handoff-1"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %s to be preserved: %s", want, s)
		}
	}

	// Removing foreign seal leaves only own + unknown; second call does nothing.
	if out2, _, ok2 := withoutObservedForeignReasoning(out, target); ok2 || out2 != nil {
		t.Fatalf("expected second pass to be a no-op, got ok=%v out=%s", ok2, out2)
	}
}

type forkMockCopilot struct {
	mu             sync.Mutex
	calls          [][]byte
	paths          []string
	ownSeals       map[string]bool
	failAfter      bool
	alwaysEmpty400 bool
	responseIdx    int
}

func (m *forkMockCopilot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.calls = append(m.calls, b)
	m.paths = append(m.paths, r.URL.Path)
	alwaysEmpty400 := m.alwaysEmpty400
	m.mu.Unlock()

	if r.URL.Path == "/chat/completions" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chat_1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"CARBON_OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)
		return
	}
	if alwaysEmpty400 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":{"message":"","code":"invalid_request_body"}}`)
		return
	}

	var q struct {
		Stream bool         `json:"stream"`
		Input  []sealedItem `json:"input"`
	}
	_ = json.Unmarshal(b, &q)
	for _, it := range q.Input {
		if it.Type == "reasoning" && it.Enc != "" {
			if m.ownSeals == nil || !m.ownSeals[it.Enc] {
				if strings.HasPrefix(it.Enc, "gAAAA-codex") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					io.WriteString(w, `{"error":{"message":"","code":"invalid_request_body"}}`)
					return
				}
			}
		}
	}
	if m.failAfter {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":{"message":"copilot backend down","code":"internal_error"}}`)
		return
	}
	m.mu.Lock()
	m.responseIdx++
	newSeal := fmt.Sprintf("gAAAA-copilot-seal-%d", m.responseIdx)
	if m.ownSeals == nil {
		m.ownSeals = map[string]bool{}
	}
	m.ownSeals[newSeal] = true
	m.mu.Unlock()

	doneMsg := `{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"COPILOT_DONE"}]}`
	reasonItem := `{"type":"reasoning","id":"rs_cop_1","status":"completed","summary":[],"encrypted_content":"` + newSeal + `"}`
	if q.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(
			`data: {"type":"response.created","response":{"id":"resp_c1","status":"in_progress"}}`,
			`data: {"type":"response.output_item.done","output_index":0,"item":`+reasonItem+`}`,
			`data: {"type":"response.output_item.done","output_index":1,"item":`+doneMsg+`}`,
			`data: {"type":"response.completed","response":{"id":"resp_c1","status":"completed","output":[`+reasonItem+`,`+doneMsg+`],"usage":{"input_tokens":5,"output_tokens":2}}}`,
		))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"id":"resp_c1","object":"response","status":"completed","output":[`+reasonItem+`,`+doneMsg+`],"usage":{"input_tokens":5,"output_tokens":2}}`)
}

func (m *forkMockCopilot) asked() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.calls...)
}

func setupForkCopilotAndCodex(t *testing.T, cop *forkMockCopilot, codexSeal string) {
	t.Helper()
	fresh(t)
	resetSealIssuersForTest()

	codexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reasonItem := `{"type":"reasoning","id":"rs_codex_1","status":"completed","summary":[],"encrypted_content":"` + codexSeal + `"}`
		doneMsg := `{"type":"message","id":"msg_cdx_1","role":"assistant","content":[{"type":"output_text","text":"CODEX_DONE"}]}`
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(
			`data: {"type":"response.created","response":{"id":"resp_x1","status":"in_progress"}}`,
			`data: {"type":"response.output_item.done","output_index":0,"item":`+reasonItem+`}`,
			`data: {"type":"response.output_item.done","output_index":1,"item":`+doneMsg+`}`,
			`data: {"type":"response.completed","response":{"id":"resp_x1","status":"completed","output":[`+reasonItem+`,`+doneMsg+`],"usage":{"input_tokens":4,"output_tokens":2}}}`,
		))
	}))
	t.Cleanup(codexSrv.Close)
	oldCodexBase := provider.CodexBase
	provider.CodexBase = codexSrv.URL + "/backend-api/codex"
	t.Cleanup(func() { provider.CodexBase = oldCodexBase })

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models":
			io.WriteString(w, `{"data":[`+
				`{"id":"gpt-6.2-sol","name":"GPT-6.2-Sol","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/responses"],"capabilities":{"type":"chat","supports":{"reasoning_effort":["low","medium","high"]}}},`+
				`{"id":"gemini-4-carbon","name":"Gemini-4-Carbon","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}}`+
				`]}`)
		case "/responses", "/chat/completions":
			cop.ServeHTTP(w, r)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(api.Close)

	cfg := os.Getenv("XDG_CONFIG_HOME")
	os.MkdirAll(filepath.Join(cfg, "github-copilot"), 0o755)
	os.WriteFile(filepath.Join(cfg, "github-copilot", "apps.json"), mustJSON(map[string]any{
		"github.com:Iv1.x": map[string]any{"user": "alice", "oauth_token": "gho_alice"},
	}), 0o600)

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "sess",
				"expires_at": time.Now().Add(time.Hour).Unix(),
				"endpoints":  map[string]string{"api": api.URL},
			})
			return
		}
		io.WriteString(w, `{"copilot_plan":"individual"}`)
	}))
	t.Cleanup(gh.Close)
	oldTok, oldUser := provider.CopilotTokenURL, provider.CopilotUserURL
	provider.CopilotTokenURL, provider.CopilotUserURL = gh.URL+"/token", gh.URL+"/user"
	t.Cleanup(func() { provider.CopilotTokenURL, provider.CopilotUserURL = oldTok, oldUser })
}

func codexBackendPost(t *testing.T, s *Server, body string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", CodexPath+"/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer chatgpt-tok")
	req.Header.Set("chatgpt-account-id", "acct-codex-1")
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func gatewayPost(t *testing.T, s *Server, path, body string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", codexUA)
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestForkCodexToCopilotReasoningHandoffAndProactiveLearn(t *testing.T) {
	cop := &forkMockCopilot{}
	codexSeal := "gAAAA-codex-turn1-seal"
	setupForkCopilotAndCodex(t, cop, codexSeal)
	s := New()

	// Turn 1: Codex backend emits a sealed reasoning item.
	turn1 := `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"thread-handoff-1","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"step 1"}]}]}`
	if code, out := codexBackendPost(t, s, turn1); code != 200 || !strings.Contains(out, "CODEX_DONE") {
		t.Fatalf("codex turn 1 failed: %d %s", code, out)
	}

	// Turn 2: switched to Copilot GPT-6.2-Sol carrying Codex seal + unobserved seal.
	turn2 := `{"model":"copilot/gpt-6.2-sol","stream":true,"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"thread-handoff-1","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"step 1"}]},` +
		`{"type":"reasoning","id":"rs_codex_1","summary":[],"encrypted_content":"` + codexSeal + `"},` +
		`{"type":"reasoning","id":"rs_unknown_1","summary":[],"encrypted_content":"gAAAA-unknown-seal"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"step 2"}]}` +
		`]}`
	code, out := gatewayPost(t, s, "/v1/responses", turn2)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 2 failed: %d %s", code, out)
	}
	calls := cop.asked()
	if len(calls) != 2 {
		t.Fatalf("copilot calls on turn 2 = %d, want 2 (400 then clean retry)", len(calls))
	}
	if !strings.Contains(string(calls[0]), codexSeal) {
		t.Fatalf("attempt 0 should have carried codex seal: %s", calls[0])
	}
	if strings.Contains(string(calls[1]), codexSeal) {
		t.Fatalf("attempt 1 should have stripped codex seal: %s", calls[1])
	}
	if !strings.Contains(string(calls[1]), "gAAAA-unknown-seal") || !strings.Contains(string(calls[1]), "thread-handoff-1") {
		t.Fatalf("attempt 1 lost unknown seal or cache key: %s", calls[1])
	}
	if r := lastRoute(s); len(r.Tries) != 2 || r.Tries[0].Fail != failForeign || r.Tries[1].Status != 200 {
		t.Fatalf("unexpected route tries: %+v", r.Tries)
	}

	// Turn 3: carries both Codex seal (proactively stripped!) and Copilot's own seal (preserved!).
	turn3 := `{"model":"copilot/gpt-6.2-sol","stream":true,"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"thread-handoff-1","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"step 1"}]},` +
		`{"type":"reasoning","id":"rs_codex_1","summary":[],"encrypted_content":"` + codexSeal + `"},` +
		`{"type":"reasoning","id":"rs_cop_1","summary":[],"encrypted_content":"gAAAA-copilot-seal-1"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"step 3"}]}` +
		`]}`
	code, out = gatewayPost(t, s, "/v1/responses", turn3)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 3 failed: %d %s", code, out)
	}
	calls = cop.asked()
	if len(calls) != 3 {
		t.Fatalf("expected proactive stripping (1 call on turn 3), total calls=%d", len(calls))
	}
	if strings.Contains(string(calls[2]), codexSeal) || !strings.Contains(string(calls[2]), "gAAAA-copilot-seal-1") {
		t.Fatalf("turn 3 body mismatch: %s", calls[2])
	}
}

func TestForkCodexToCopilotCarbonToSolWithCodexSeal(t *testing.T) {
	cop := &forkMockCopilot{}
	codexSeal := "gAAAA-codex-via-carbon"
	setupForkCopilotAndCodex(t, cop, codexSeal)
	s := New()

	// Turn 1 on Codex backend.
	if code, _ := codexBackendPost(t, s, `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"thread-carbon-sol","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 {
		t.Fatal("codex turn 1 failed")
	}
	// Turn 2 via Copilot Carbon on /chat/completions.
	if code, out := gatewayPost(t, s, "/v1/chat/completions", `{"model":"copilot/gemini-4-carbon","messages":[{"role":"user","content":"t2"}]}`); code != 200 || !strings.Contains(out, "CARBON_OK") {
		t.Fatalf("carbon turn 2 failed: %d %s", code, out)
	}
	// Turn 3 switches back to Responses on Copilot Sol while Turn 1's Codex seal is still in history.
	turn3 := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-carbon-sol","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]},` +
		`{"type":"reasoning","id":"rs_codex_1","summary":[],"encrypted_content":"` + codexSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t3"}]}` +
		`]}`
	code, out := gatewayPost(t, s, "/v1/responses", turn3)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("sol turn 3 failed: %d %s", code, out)
	}
	calls := cop.asked()
	if len(calls) != 3 { // 1 chat completion + 2 responses
		t.Fatalf("calls=%d, want 3", len(calls))
	}
	if !strings.Contains(string(calls[1]), codexSeal) || strings.Contains(string(calls[2]), codexSeal) {
		t.Fatalf("expected Sol retry to strip Codex seal: call1=%s call2=%s", calls[1], calls[2])
	}
}

func TestForkCodexToCopilotFailedRetryDoesNotLearnOrPolluteFallback(t *testing.T) {
	cop := &forkMockCopilot{failAfter: true}
	codexSeal := "gAAAA-codex-fail-case"
	setupForkCopilotAndCodex(t, cop, codexSeal)

	var fbCalls [][]byte
	var fbMu sync.Mutex
	fb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fbMu.Lock()
		fbCalls = append(fbCalls, b)
		fbMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"resp_fb","object":"response","status":"completed","output":[{"type":"message","id":"msg_fb","role":"assistant","content":[{"type":"output_text","text":"FB_OK"}]}],"usage":{"input_tokens":3,"output_tokens":1}}`)
	}))
	t.Cleanup(fb.Close)
	if err := provider.Save(provider.Provider{
		ID: "fb", Name: "Fallback", Key: "sk-fb", Models: []string{"gpt-6.2-sol"}, Responses: fb.URL + "/v1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := provider.SaveGroup(provider.Group{
		Name:    "handoff",
		Members: []string{"copilot/gpt-6.2-sol", "fb/gpt-6.2-sol"},
		Routing: provider.Ordered,
	}); err != nil {
		t.Fatal(err)
	}

	s := New()
	if code, _ := codexBackendPost(t, s, `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"thread-fail-nolearn","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 {
		t.Fatal("codex turn 1 failed")
	}

	reqBody := `{"model":"group/handoff","stream":false,"store":false,"prompt_cache_key":"thread-fail-nolearn","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]},` +
		`{"type":"reasoning","id":"rs_codex_1","summary":[],"encrypted_content":"` + codexSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}` +
		`]}`
	code, out := gatewayPost(t, s, "/v1/responses", reqBody)
	if code != 200 || !strings.Contains(out, "FB_OK") {
		t.Fatalf("group fallback failed: %d %s", code, out)
	}
	fbMu.Lock()
	fbCount := len(fbCalls)
	var fbBody string
	if fbCount > 0 {
		fbBody = string(fbCalls[0])
	}
	fbMu.Unlock()
	if fbCount != 1 || !strings.Contains(fbBody, codexSeal) {
		t.Fatalf("fallback should receive original untouched seal (count=%d): %s", fbCount, fbBody)
	}

	// Because Copilot's retry failed (500), it must NOT have learned via noteRefused:
	// hitting copilot/gpt-6.2-sol directly again on the same thread still sends codexSeal first.
	cop.mu.Lock()
	cop.failAfter = false
	before := len(cop.calls)
	cop.mu.Unlock()
	if code, out := gatewayPost(t, s, "/v1/responses", strings.Replace(reqBody, "group/handoff", "copilot/gpt-6.2-sol", 1)); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("direct copilot after failed retry failed: %d %s", code, out)
	}
	afterCalls := cop.asked()[before:]
	if len(afterCalls) != 2 || !strings.Contains(string(afterCalls[0]), codexSeal) || strings.Contains(string(afterCalls[1]), codexSeal) {
		t.Fatalf("expected unlearned copilot to send seal on attempt 0 and strip on attempt 1 (calls=%d)", len(afterCalls))
	}
}

func TestForkRefusedSealsAndIssuerConcurrency(t *testing.T) {
	resetSealIssuersForTest()
	const n = 16
	body := `{"model":"gpt-6.2-sol","input":[{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAA-race-seal"}]}`

	var wg sync.WaitGroup
	for g := range n {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			seal := "gAAAA-race-seal"
			sum := sha256.Sum256([]byte(seal))
			for iter := range 50 {
				enc := seal
				if iter%3 == 0 {
					enc = "gAAAA-race-" + strconv.Itoa(id) + "-" + strconv.Itoa(iter)
				}
				recordSealIssuer(enc, "codex|acct")
				_, _ = sealIssuerOf(enc)
				noteRefused("conv-race", "copilot|alice", [][sha256.Size]byte{sum, sha256.Sum256([]byte(enc))})
				_, _ = withoutRefused("conv-race", "copilot|alice", []byte(body))
				_, _, _ = withoutObservedForeignReasoning([]byte(body), "copilot|alice")
			}
		}(g)
	}
	wg.Wait()
}

func TestForkSealIssuersPersistAcrossRestart(t *testing.T) {
	cop := &forkMockCopilot{}
	codexSeal := "gAAAA-codex-before-restart"
	setupForkCopilotAndCodex(t, cop, codexSeal)
	s := New()

	// Turn 1: Codex produces codexSeal; Turn 2: Copilot produces its own seal.
	if code, _ := codexBackendPost(t, s, `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"thread-restart","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 {
		t.Fatal("codex turn 1 failed")
	}
	turn2 := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-restart","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}]}`
	if code, out := gatewayPost(t, s, "/v1/responses", turn2); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 2 failed: %d %s", code, out)
	}
	copilotSeal := "gAAAA-copilot-seal-1"

	// Disk file must hold only SHA-256 digests, never plaintext seals.
	diskPath := sealIssuersPath()
	raw, err := os.ReadFile(diskPath)
	if err != nil {
		t.Fatalf("expected persisted seal issuers file at %s: %v", diskPath, err)
	}
	if strings.Contains(string(raw), codexSeal) || strings.Contains(string(raw), copilotSeal) {
		t.Fatalf("plaintext seal leaked into persisted file: %s", raw)
	}

	// Simulate full process restart: clear in-memory sealIssuers & refusedSeals, construct new Server.
	clearSealIssuersMemoryForRestart()
	s2 := New()

	// Turn 3 after restart carries both codexSeal and copilotSeal plus an unobserved unknown seal.
	// Persisted sealIssuers lets stage 1 strip ONLY codexSeal, keeping copilotSeal & unknownSeal intact.
	unknownSeal := "gAAAA-unrelated-unobserved-ok"
	turn3 := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-restart","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]},` +
		`{"type":"reasoning","id":"rs_codex_1","summary":[],"encrypted_content":"` + codexSeal + `"},` +
		`{"type":"reasoning","id":"rs_cop_1","summary":[],"encrypted_content":"` + copilotSeal + `"},` +
		`{"type":"reasoning","id":"rs_unk_1","summary":[],"encrypted_content":"` + unknownSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t3"}]}` +
		`]}`
	before := len(cop.asked())
	code, out := gatewayPost(t, s2, "/v1/responses", turn3)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("post-restart handoff failed: %d %s", code, out)
	}
	calls := cop.asked()[before:]
	if len(calls) != 2 {
		t.Fatalf("expected attempt 0 + stage-1 retry (2 calls), got %d", len(calls))
	}
	retryBody := string(calls[1])
	if strings.Contains(retryBody, codexSeal) {
		t.Fatalf("stage-1 retry should strip persisted codexSeal: %s", retryBody)
	}
	if !strings.Contains(retryBody, copilotSeal) || !strings.Contains(retryBody, unknownSeal) {
		t.Fatalf("stage-1 retry should preserve copilotSeal and unknownSeal: %s", retryBody)
	}

	// Corrupt disk file and expired entries degrade gracefully without breaking writes.
	if err := os.WriteFile(diskPath, []byte("{corrupt-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	clearSealIssuersMemoryForRestart()
	if _, known := sealIssuerOf(codexSeal); known {
		t.Fatal("expected corrupt file to load as empty")
	}
	recordSealIssuer("gAAAA-fresh-after-corrupt", "codex-relay|chatgpt.com")
	clearSealIssuersMemoryForRestart()
	if got, known := sealIssuerOf("gAAAA-fresh-after-corrupt"); !known || got != "codex-relay|chatgpt.com" {
		t.Fatalf("expected recovery after corrupt file, got (%q, %v)", got, known)
	}

	// Expired entries (>14d) are pruned on load.
	expiredHex := fmt.Sprintf("%x", sha256.Sum256([]byte("gAAAA-expired-seal")))
	validHex := fmt.Sprintf("%x", sha256.Sum256([]byte("gAAAA-valid-seal")))
	expiredJSON, _ := json.Marshal(sealIssuersDisk{
		Version: 1,
		Entries: map[string]sealIssuersDiskEntry{
			expiredHex: {Issuer: "codex-relay|chatgpt.com", AtUnix: time.Now().Add(-15 * 24 * time.Hour).Unix()},
			validHex:   {Issuer: "codex-relay|chatgpt.com", AtUnix: time.Now().Add(-2 * 24 * time.Hour).Unix()},
		},
	})
	if err := os.WriteFile(diskPath, expiredJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	clearSealIssuersMemoryForRestart()
	if _, known := sealIssuerOf("gAAAA-expired-seal"); known {
		t.Fatal("expected 15-day-old seal to be pruned on load")
	}
	if got, known := sealIssuerOf("gAAAA-valid-seal"); !known || got != "codex-relay|chatgpt.com" {
		t.Fatalf("expected 2-day-old seal to reload, got (%q, %v)", got, known)
	}
}

func TestForkCopilotHandoffUnknownFallbackPreservesOwnSeal(t *testing.T) {
	cop := &forkMockCopilot{}
	setupForkCopilotAndCodex(t, cop, "gAAAA-codex-unused")
	s := New()

	// Turn 1: Copilot issues its own seal (observed & persisted).
	if code, out := gatewayPost(t, s, "/v1/responses", `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-unknown-fb","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 1 failed: %d %s", code, out)
	}
	copilotSeal := "gAAAA-copilot-seal-1"
	// Unobserved foreign seal (e.g. from another computer / >14 days old, never recorded in sealIssuers).
	unobservedForeign := "gAAAA-codex-from-other-machine"

	turn2 := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-unknown-fb","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t0"}]},` +
		`{"type":"reasoning","id":"rs_old_foreign","summary":[],"encrypted_content":"` + unobservedForeign + `"},` +
		`{"type":"compaction","id":"cmp_keep","encrypted_content":"gAAAA-compaction-keep"},` +
		`{"type":"reasoning","id":"rs_cop_own","summary":[],"encrypted_content":"` + copilotSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}` +
		`]}`
	before := len(cop.asked())
	code, out := gatewayPost(t, s, "/v1/responses", turn2)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("unknown fallback failed: %d %s", code, out)
	}
	calls := cop.asked()[before:]
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (attempt 0 + stage-2 fallback directly), got %d", len(calls))
	}
	retryBody := string(calls[1])
	if strings.Contains(retryBody, unobservedForeign) {
		t.Fatalf("stage-2 fallback should strip unobserved foreign seal: %s", retryBody)
	}
	if !strings.Contains(retryBody, copilotSeal) || !strings.Contains(retryBody, "cmp_keep") {
		t.Fatalf("stage-2 fallback must keep known own seal and compaction: %s", retryBody)
	}

	// Turn 3: refusedSeals learned unobservedForeign, so turn 3 succeeds on attempt 0 (1 call).
	before3 := len(cop.asked())
	if code, out := gatewayPost(t, s, "/v1/responses", turn2); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("turn 3 failed: %d %s", code, out)
	}
	calls3 := cop.asked()[before3:]
	if len(calls3) != 1 || strings.Contains(string(calls3[0]), unobservedForeign) || !strings.Contains(string(calls3[0]), copilotSeal) {
		t.Fatalf("expected proactive strip on turn 3 (calls=%d): %s", len(calls3), string(calls3[0]))
	}
}

func TestForkCopilotHandoffTwoStageKnownThenUnknown(t *testing.T) {
	cop := &forkMockCopilot{}
	knownForeign := "gAAAA-codex-known"
	setupForkCopilotAndCodex(t, cop, knownForeign)
	s := New()

	// Observe knownForeign from Codex and copilotSeal from Copilot.
	if code, _ := codexBackendPost(t, s, `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"thread-2stage","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 {
		t.Fatal("codex turn 1 failed")
	}
	if code, out := gatewayPost(t, s, "/v1/responses", `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-2stage","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}]}`); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 2 failed: %d %s", code, out)
	}
	copilotSeal := "gAAAA-copilot-seal-1"
	unknownForeign := "gAAAA-codex-unobserved-older"

	turn3 := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-2stage","input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t0"}]},` +
		`{"type":"reasoning","id":"rs_unk","summary":[],"encrypted_content":"` + unknownForeign + `"},` +
		`{"type":"reasoning","id":"rs_known","summary":[],"encrypted_content":"` + knownForeign + `"},` +
		`{"type":"reasoning","id":"rs_own","summary":[],"encrypted_content":"` + copilotSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t3"}]}` +
		`]}`
	before := len(cop.asked())
	code, out := gatewayPost(t, s, "/v1/responses", turn3)
	if code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("two-stage recovery failed: %d %s", code, out)
	}
	calls := cop.asked()[before:]
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (raw -> stage 1 -> stage 2), got %d", len(calls))
	}
	// Stage 1 stripped knownForeign, kept unknownForeign + copilotSeal.
	if strings.Contains(string(calls[1]), knownForeign) || !strings.Contains(string(calls[1]), unknownForeign) || !strings.Contains(string(calls[1]), copilotSeal) {
		t.Fatalf("unexpected stage-1 body: %s", calls[1])
	}
	// Stage 2 stripped unknownForeign too, still kept copilotSeal.
	if strings.Contains(string(calls[2]), knownForeign) || strings.Contains(string(calls[2]), unknownForeign) || !strings.Contains(string(calls[2]), copilotSeal) {
		t.Fatalf("unexpected stage-2 body: %s", calls[2])
	}

	// Turn 4: BOTH knownForeign and unknownForeign must have been learned into refusedSeals (1 call only).
	before4 := len(cop.asked())
	if code, out := gatewayPost(t, s, "/v1/responses", turn3); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("turn 4 failed: %d %s", code, out)
	}
	calls4 := cop.asked()[before4:]
	if len(calls4) != 1 || strings.Contains(string(calls4[0]), knownForeign) || strings.Contains(string(calls4[0]), unknownForeign) || !strings.Contains(string(calls4[0]), copilotSeal) {
		t.Fatalf("expected both foreign seals proactively stripped on turn 4 (calls=%d): %s", len(calls4), string(calls4[0]))
	}
}

func TestForkCopilotHandoffOwnOnlyAndUnrelated400NoFalseLearn(t *testing.T) {
	cop := &forkMockCopilot{}
	setupForkCopilotAndCodex(t, cop, "gAAAA-codex-unused")
	s := New()

	// Produce one known Copilot-own seal first.
	if code, out := gatewayPost(t, s, "/v1/responses", `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-own-only","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"t1"}]}]}`); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("copilot turn 1 failed: %d %s", code, out)
	}
	copilotSeal := "gAAAA-copilot-seal-1"

	// (a) Unrelated empty 400 with ONLY known target-own seal: must NOT retry or drop own seal.
	cop.mu.Lock()
	cop.alwaysEmpty400 = true
	cop.mu.Unlock()
	ownOnlyReq := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-own-only","input":[` +
		`{"type":"reasoning","id":"rs_own","summary":[],"encrypted_content":"` + copilotSeal + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}` +
		`]}`
	beforeA := len(cop.asked())
	if code, _ := gatewayPost(t, s, "/v1/responses", ownOnlyReq); code != 400 {
		t.Fatalf("expected 400 for unrelated own-only error, got %d", code)
	}
	if callsA := cop.asked()[beforeA:]; len(callsA) != 1 {
		t.Fatalf("expected 0 retries when only known own seal is present, got %d calls", len(callsA))
	}

	// (b) Unrelated empty 400 with an unknown seal: retries once without unknown seal, still gets 400,
	// and MUST NOT record the unknown seal into refusedSeals.
	unknownBenign := "gAAAA-benign-unknown-seal"
	unkReq := `{"model":"copilot/gpt-6.2-sol","stream":false,"store":false,"prompt_cache_key":"thread-unrelated-unk","input":[` +
		`{"type":"reasoning","id":"rs_unk","summary":[],"encrypted_content":"` + unknownBenign + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"t2"}]}` +
		`]}`
	beforeB := len(cop.asked())
	if code, _ := gatewayPost(t, s, "/v1/responses", unkReq); code != 400 {
		t.Fatalf("expected 400 for persistent unrelated error, got %d", code)
	}
	if callsB := cop.asked()[beforeB:]; len(callsB) != 2 || strings.Contains(string(callsB[1]), unknownBenign) {
		t.Fatalf("expected 1 retry without unknown seal, got %d calls", len(callsB))
	}

	// Once the unrelated 400 clears, unknownBenign must still be sent untouched on the next turn.
	cop.mu.Lock()
	cop.alwaysEmpty400 = false
	cop.mu.Unlock()
	beforeC := len(cop.asked())
	if code, out := gatewayPost(t, s, "/v1/responses", unkReq); code != 200 || !strings.Contains(out, "COPILOT_DONE") {
		t.Fatalf("expected 200 after unrelated 400 cleared, got %d %s", code, out)
	}
	if callsC := cop.asked()[beforeC:]; len(callsC) != 1 || !strings.Contains(string(callsC[0]), unknownBenign) {
		t.Fatalf("unknown seal must not be falsely learned into refusedSeals (calls=%d): %s", len(callsC), string(callsC[0]))
	}
}
