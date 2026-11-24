package gateway

import (
	"encoding/json"

	"github.com/tidwall/gjson"
	"github.com/yetone/magpie/internal/claudeseal"
)

// Claude's signed reasoning through a Responses client (mysterious_dove_96933
// on Discord): a reply's reasoning item carries Claude's thinking block,
// signature and all, or its redacted_thinking block, in encrypted_content
// (claudeseal), and the next request reads it back into the block as
// Claude wrote it, which Anthropic wants back on a tool loop's next turn.

// claudeThinking is the encrypted_content of a reasoning item for Claude's
// thinking block with its signature.
func claudeThinking(text, signature string) string {
	b, _ := json.Marshal(struct {
		Type      string `json:"type"`
		Thinking  string `json:"thinking"`
		Signature string `json:"signature"`
	}{"thinking", text, signature})
	return claudeseal.Seal(b)
}

// claudePart is the reasoning a block magpie sealed stands for: Claude's
// thinking, signed, or its redacted_thinking whole; summary (the item's
// own reasoning, as it is without one) when the block can't be read.
func claudePart(block json.RawMessage, summary Part) Part {
	var b struct {
		Type      string `json:"type"`
		Thinking  string `json:"thinking"`
		Signature string `json:"signature"`
		Data      string `json:"data"`
	}
	if block == nil || decodeJSON(block, &b) != nil {
		return summary
	}
	switch {
	case b.Type == "thinking" && b.Signature != "":
		return Part{Kind: Thinking, Text: b.Thinking, Signature: b.Signature, SignedBy: sealAnthropic}
	case b.Type == "redacted_thinking" && b.Data != "":
		return Part{Kind: Thinking, Sealed: block, SealedBy: sealAnthropic}
	}
	return summary
}

// withoutClaudeSeals is a Responses request body with no Claude-sealed
// reasoning items (#6774): Responses APIs reject reasoning items whose
// encrypted_content was stripped without stored state, so Claude-sealed
// reasoning items are removed whole. Every other item, and a body with none,
// goes byte for byte.
func withoutClaudeSeals(body []byte) []byte {
	if !bodyHas(body, claudeseal.Mark) {
		return body
	}
	var q map[string]json.RawMessage
	var input []json.RawMessage
	if decodeJSON(body, &q) != nil || decodeJSON(q["input"], &input) != nil {
		return body
	}
	out := make([]json.RawMessage, 0, len(input))
	changed := false
	for _, it := range input {
		r := gjson.ParseBytes(it)
		if r.Get("type").String() != "reasoning" || !claudeseal.Is(r.Get("encrypted_content").String()) {
			out = append(out, it)
			continue
		}
		changed = true
	}
	if !changed {
		return body
	}
	q["input"], _ = json.Marshal(out)
	b, err := json.Marshal(q)
	if err != nil {
		return body
	}
	return b
}
