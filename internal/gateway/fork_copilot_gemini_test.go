package gateway

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tidwall/gjson"
)

func TestForkCopilotChatReasoningTextToAnthropicAndResponses(t *testing.T) {
	chunks := []string{
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","reasoning_text":"Step 1: check cache."}}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning_text":" Step 2: reply."}}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Done."},"finish_reason":"stop"}]}`,
		`[DONE]`,
	}

	anthEvents := chatToAnthropic(t, chunks...)
	var anthThink, anthText strings.Builder
	for _, ev := range anthEvents {
		if ev["type"] == "content_block_delta" {
			delta, _ := ev["delta"].(map[string]any)
			if delta["type"] == "thinking_delta" {
				s, _ := delta["thinking"].(string)
				anthThink.WriteString(s)
			}
			if delta["type"] == "text_delta" {
				s, _ := delta["text"].(string)
				anthText.WriteString(s)
			}
		}
	}
	if anthThink.String() != "Step 1: check cache. Step 2: reply." || anthText.String() != "Done." {
		t.Fatalf("anthropic translation got think=%q text=%q", anthThink.String(), anthText.String())
	}

	respEvents := chatToResponses(t, chunks...)
	var respThink, respText strings.Builder
	for _, ev := range respEvents {
		switch ev["type"] {
		case "response.reasoning_summary_text.delta":
			s, _ := ev["delta"].(string)
			respThink.WriteString(s)
		case "response.output_text.delta":
			s, _ := ev["delta"].(string)
			respText.WriteString(s)
		}
	}
	if respThink.String() != "Step 1: check cache. Step 2: reply." || respText.String() != "Done." {
		t.Fatalf("responses translation got think=%q text=%q", respThink.String(), respText.String())
	}

	content, text, reasoning, _ := timingKind([]byte("data: " + chunks[0]))
	if !content || text || !reasoning {
		t.Fatalf("timingKind(reasoning_text) = (%v,%v,%v), want (true,false,true)", content, text, reasoning)
	}
	var tail chatTail
	tail.see([]byte(chunks[0]))
	if !tail.thought {
		t.Fatal("chatTail.see did not recognize delta.reasoning_text")
	}
}

func TestForkCopilotGeminiThinkingRoomAndThinkOff(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	copilotAPIFake(t, map[string]string{
		"gemini-4-carbon": `["/chat/completions"]`,
		"gemini-4-neon":   `["/chat/completions"]`,
		"gpt-4.1":         `["/chat/completions"]`,
	}, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/chat/completions" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		mu.Lock()
		sent = append(sent, string(b))
		mu.Unlock()
		model := modelOf(b)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(
			`data: {"id":"c1","model":"`+model+`","choices":[{"index":0,"delta":{"role":"assistant","reasoning_text":"Brief thought"}}]}`,
			`data: {"id":"c1","model":"`+model+`","choices":[{"index":0,"delta":{"content":"Short Title"},"finish_reason":"stop"}]}`,
			`data: [DONE]`))
	})

	server := New()
	cases := []struct {
		name       string
		path       string
		body       string
		wantMax    int64
		wantEffort string
	}{
		{
			name:       "messages small max_tokens no thinking gets high room",
			path:       "/v1/messages",
			body:       `{"model":"copilot/gemini-4-carbon","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Title?"}]}`,
			wantMax:    64 + 24000,
			wantEffort: "",
		},
		{
			name:       "messages thinking disabled maps to low effort and low room",
			path:       "/v1/messages",
			body:       `{"model":"copilot/gemini-4-neon","max_tokens":64,"stream":true,"thinking":{"type":"disabled"},"messages":[{"role":"user","content":"Title?"}]}`,
			wantMax:    64 + 4096,
			wantEffort: "low",
		},
		{
			name:       "messages explicit adaptive low keeps caller max_tokens",
			path:       "/v1/messages",
			body:       `{"model":"copilot/gemini-4-carbon","max_tokens":512,"stream":true,"thinking":{"type":"adaptive"},"output_config":{"effort":"low"},"messages":[{"role":"user","content":"Title?"}]}`,
			wantMax:    512,
			wantEffort: "low",
		},
		{
			name:       "responses effort none maps to low effort and low room",
			path:       "/v1/responses",
			body:       `{"model":"copilot/gemini-4-neon","max_output_tokens":512,"stream":true,"reasoning":{"effort":"none"},"input":"Title?"}`,
			wantMax:    512 + 4096,
			wantEffort: "low",
		},
		{
			name:       "non-gemini copilot model stays untouched",
			path:       "/v1/messages",
			body:       `{"model":"copilot/gpt-4.1","max_tokens":64,"stream":true,"thinking":{"type":"disabled"},"messages":[{"role":"user","content":"Title?"}]}`,
			wantMax:    64,
			wantEffort: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sent)
			out := postOpaque(t, server, tc.path, tc.body)
			if len(sent) != before+1 {
				t.Fatalf("expected 1 upstream call, got %d", len(sent)-before)
			}
			gotBody := sent[before]
			if gotMax := gjson.Get(gotBody, "max_tokens").Int(); gotMax != tc.wantMax {
				t.Fatalf("upstream max_tokens = %d, want %d (body=%s)", gotMax, tc.wantMax, gotBody)
			}
			if gotEffort := gjson.Get(gotBody, "reasoning_effort").Str; gotEffort != tc.wantEffort {
				t.Fatalf("upstream reasoning_effort = %q, want %q (body=%s)", gotEffort, tc.wantEffort, gotBody)
			}
			if tc.path == "/v1/messages" && strings.Contains(tc.body, "gemini") && !strings.Contains(out, `"thinking_delta"`) {
				t.Fatalf("expected thinking_delta from Copilot reasoning_text in Anthropic SSE: %s", out)
			}
			if tc.path == "/v1/responses" && !strings.Contains(out, `"response.reasoning_summary_text.delta"`) {
				t.Fatalf("expected reasoning_summary_text.delta from Copilot reasoning_text in Responses SSE: %s", out)
			}
		})
	}
}
