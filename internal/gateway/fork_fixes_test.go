package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

func TestCopilotGeminiAssistantLastPrefillRefusal(t *testing.T) {
	const copilotGeminiErr = `{"error":{"message":"Copilot: The last message in a Gemini request must not be from the assistant. Ensure the conversation ends with a user or tool message.","code":"invalid_request_body"}}`
	const unrelatedErr = `{"error":{"message":"Copilot: invalid model parameter","code":"invalid_request_body"}}`

	if !refusesPrefill(http.StatusBadRequest, []byte(copilotGeminiErr)) {
		t.Fatalf("expected refusesPrefill to match Copilot Gemini assistant-last message")
	}
	if refusesPrefill(http.StatusBadRequest, []byte(unrelatedErr)) {
		t.Fatalf("unexpected refusesPrefill match for unrelated 400")
	}
	if refusesPrefill(http.StatusTooManyRequests, []byte(copilotGeminiErr)) {
		t.Fatalf("unexpected refusesPrefill match for non-400 status")
	}

	f := &noPrefill{proto: provider.Chat, refuse: copilotGeminiErr}
	post := prefillServer(t, f)

	ask := `{"model":"up/m","stream":false,"messages":[{"role":"user","content":"Reply with OK"},{"role":"assistant","content":"O"}]}`
	code, body := post("/v1/chat/completions", ask)
	if code != http.StatusOK || !strings.Contains(body, `"OK"`) {
		t.Fatalf("status=%d body=%s, want 200 OK after Continue retry", code, body)
	}
	if f.calls() != 2 || f.lastUser(1) != continueText {
		t.Fatalf("calls=%d lastUser(1)=%q, want 2 calls with %q", f.calls(), f.lastUser(1), continueText)
	}

	// Second request should append Continue. immediately on first attempt.
	code, _ = post("/v1/chat/completions", ask)
	if code != http.StatusOK || f.calls() != 3 || f.lastUser(2) != continueText {
		t.Fatalf("status=%d calls=%d lastUser(2)=%q, want prefillRefused remembered", code, f.calls(), f.lastUser(2))
	}
}
