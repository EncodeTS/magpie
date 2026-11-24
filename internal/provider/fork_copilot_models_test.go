package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCopilotModelsMaxOutputTokens(t *testing.T) {
	signIn(t)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			_, _ = w.Write([]byte(`{"data":[
				{
					"id":"gemini-4-carbon",
					"name":"Gemini 4 Carbon",
					"model_picker_enabled":true,
					"supported_endpoints":["/chat/completions"],
					"capabilities":{"type":"chat","limits":{"max_prompt_tokens":936000,"max_output_tokens":64000}}
				},
				{
					"id":"gpt-5.5",
					"name":"GPT-5.5",
					"model_picker_enabled":true,
					"supported_endpoints":["/responses"],
					"capabilities":{"type":"chat","limits":{"max_prompt_tokens":272000}}
				}
			]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "sess",
			"expires_at": time.Now().Add(time.Hour).Unix(),
			"endpoints":  map[string]string{"api": api.URL},
		})
	}))
	defer tokens.Close()

	old := CopilotTokenURL
	CopilotTokenURL = tokens.URL
	defer func() { CopilotTokenURL = old }()
	copilotSessions = map[string]copilotSession{}

	p, ok := find(All(), "copilot")
	if !ok {
		t.Fatal("copilot provider not found")
	}
	ms, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	gotCarbon, gotGPT := -1, -1
	for _, m := range ms {
		switch m.ID {
		case "gemini-4-carbon":
			gotCarbon = m.Output
		case "gpt-5.5":
			gotGPT = m.Output
		}
	}
	if gotCarbon != 64000 {
		t.Fatalf("gemini-4-carbon Output = %d, want 64000", gotCarbon)
	}
	if gotGPT != 0 {
		t.Fatalf("gpt-5.5 Output = %d, want 0 when max_output_tokens omitted", gotGPT)
	}

	e, ok := EntryOf("copilot/gemini-4-carbon")
	if !ok {
		t.Fatal("EntryOf(copilot/gemini-4-carbon) not found")
	}
	if e.Output != 64000 || e.PublishedOutput() != 64000 {
		t.Fatalf("EntryOf Output=%d PublishedOutput=%d, want 64000 (not models.dev fallback)", e.Output, e.PublishedOutput())
	}
}
