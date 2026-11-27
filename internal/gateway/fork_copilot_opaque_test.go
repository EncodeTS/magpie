package gateway

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tidwall/gjson"
)

func copilotOpaqueFamilyUp(t *testing.T, sent *[]string) {
	t.Helper()
	var mu sync.Mutex
	copilotAPIFake(t, map[string]string{
		"gemini-4-carbon":   `["/chat/completions"]`,
		"gemini-4-neon":     `["/chat/completions"]`,
		"gemini-4-hydrogen": `["/chat/completions"]`,
		"gpt-4.1":           `["/chat/completions"]`,
	}, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/chat/completions" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		mu.Lock()
		*sent = append(*sent, string(b))
		mu.Unlock()
		model := modelOf(b)
		second := bodyHas(b, `"tool"`) || bodyHas(b, `"tool_call_id"`)
		if !gjson.GetBytes(b, "stream").Bool() {
			w.Header().Set("Content-Type", "application/json")
			if second {
				io.WriteString(w, `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Sunny in both."}}],"id":"h2","model":"`+model+`","usage":{"completion_tokens":4,"prompt_tokens":275,"total_tokens":279}}`)
				return
			}
			io.WriteString(w, `{"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"reasoning_opaque":"`+opaqueSeal+`","tool_calls":[{"function":{"arguments":"{\"city\":\"Paris\"}","name":"get_weather"},"id":"call_MHxMT2VvRVZXajFQQUtHbGY5cGY","type":"function"},{"function":{"arguments":"{\"city\":\"Tokyo\"}","name":"get_weather"},"id":"call_MXxFQ1o5R2tYeVNicnRocjV6WHg","type":"function"}]}}],"id":"h1","model":"`+model+`","usage":{"completion_tokens":88,"prompt_tokens":107,"total_tokens":195,"reasoning_tokens":48}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if second {
			io.WriteString(w, sse(
				`data: {"choices":[{"index":0,"delta":{"content":"Sunny in both.","role":"assistant"}}],"id":"h2","model":"`+model+`"}`,
				`data: {"choices":[{"finish_reason":"stop","index":0,"delta":{"content":null}}],"id":"h2","usage":{"completion_tokens":4,"prompt_tokens":275,"total_tokens":279},"model":"`+model+`"}`,
				`data: [DONE]`))
			return
		}
		io.WriteString(w, sse(
			`data: {"choices":[{"index":0,"delta":{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{\"city\":\"Paris\"}","name":"get_weather"},"id":"call_MHxMT2VvRVZXajFQQUtHbGY5cGY","index":0,"type":"function"}],"reasoning_opaque":"`+opaqueSeal+`"}}],"created":1795448456,"id":"h1","model":"`+model+`"}`,
			`data: {"choices":[{"index":0,"delta":{"content":null,"role":"assistant","tool_calls":[{"function":{"arguments":"{\"city\":\"Tokyo\"}","name":"get_weather"},"id":"call_MXxFQ1o5R2tYeVNicnRocjV6WHg","index":1,"type":"function"}]}}],"created":1795448456,"id":"h1","model":"`+model+`"}`,
			`data: {"choices":[{"finish_reason":"tool_calls","index":0,"delta":{"content":null,"role":"assistant"}}],"created":1795448456,"id":"h1","usage":{"completion_tokens":88,"prompt_tokens":107,"total_tokens":195,"reasoning_tokens":48},"model":"`+model+`"}`,
			`data: [DONE]`))
	})
}

func TestForkCopilotOpaqueSharedAcrossGeminiFamily(t *testing.T) {
	var sent []string
	copilotOpaqueFamilyUp(t, &sent)
	server := New()

	first := `{"model":"copilot/gemini-4-carbon","stream":false,"tools":` + opaqueTools + `,"messages":[{"role":"user","content":"weather in Paris and Tokyo?"}]}`
	if out := postOpaque(t, server, "/v1/chat/completions", first); !strings.Contains(out, "call_MHxMT2VvRVZXajFQQUtHbGY5cGY") {
		t.Fatalf("first carbon call failed: %s", out)
	}

	for _, dst := range []string{"copilot/gemini-4-neon", "copilot/gemini-4-hydrogen", "copilot/gemini-4-carbon"} {
		postOpaque(t, server, "/v1/chat/completions", chatSecondTurn(dst, "", false))
		if got := opaqueOn(sent[len(sent)-1]); got != opaqueSeal {
			t.Fatalf("carbon -> %s expected reasoning_opaque %q, got %q", dst, opaqueSeal, got)
		}
	}

	postOpaque(t, server, "/v1/chat/completions", chatSecondTurn("copilot/gpt-4.1", "", false))
	if got := opaqueOn(sent[len(sent)-1]); got != "" {
		t.Fatalf("carbon -> gpt-4.1 must not receive Gemini reasoning_opaque, got %q", got)
	}

	if keptOpaque("other-user", "gemini-4-neon", "call_MHxMT2VvRVZXajFQQUtHbGY5cGY") != "" {
		t.Fatal("opaque must remain isolated per Copilot account")
	}
}

func TestForkCopilotOpaqueGeminiSwitchThroughResponses(t *testing.T) {
	var sent []string
	copilotOpaqueFamilyUp(t, &sent)
	server := New()

	out := postOpaque(t, server, "/v1/responses", `{"model":"copilot/gemini-4-carbon","stream":true,"tools":[{"type":"function","name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}],"input":"weather in Paris and Tokyo?"}`)
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok && gjson.Get(data, "type").Str == "response.output_item.done" {
			if id := gjson.Get(data, "item.call_id").Str; id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 tool calls from carbon, got %v (%s)", ids, out)
	}

	second := `{"model":"copilot/gemini-4-neon","stream":true,"tools":[{"type":"function","name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}],"input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"weather in Paris and Tokyo?"}]},` +
		`{"type":"function_call","call_id":"` + ids[0] + `","name":"get_weather","arguments":"{\"city\":\"Paris\"}"},` +
		`{"type":"function_call","call_id":"` + ids[1] + `","name":"get_weather","arguments":"{\"city\":\"Tokyo\"}"},` +
		`{"type":"function_call_output","call_id":"` + ids[0] + `","output":"sunny"},` +
		`{"type":"function_call_output","call_id":"` + ids[1] + `","output":"sunny"}]}`
	postOpaque(t, server, "/v1/responses", second)
	if got := opaqueOn(sent[len(sent)-1]); got != opaqueSeal {
		t.Fatalf("responses carbon -> neon expected reasoning_opaque %q, got %q", opaqueSeal, got)
	}
}

func TestForkCopilotOpaqueLegacyExactKeyReadable(t *testing.T) {
	fresh(t)
	dir := copilotOpaqueDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, opaqueKey("echo", "gemini-4-carbon", "call_legacy_1"))
	if err := os.WriteFile(legacyPath, []byte(opaqueSeal), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := keptOpaque("echo", "gemini-4-carbon", "call_legacy_1"); got != opaqueSeal {
		t.Fatalf("legacy exact-model file should still load for same model, got %q", got)
	}
	if got := keptOpaque("echo", "gemini-4-neon", "call_legacy_1"); got != "" {
		t.Fatalf("legacy exact-model file should not falsely collide with another model, got %q", got)
	}
}
