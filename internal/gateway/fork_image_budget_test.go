package gateway

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/yetone/magpie/internal/provider"
)

func resetImageBudgetCacheForTest() {
	imageBudgetCache.mu.Lock()
	imageBudgetCache.ll = nil
	imageBudgetCache.m = map[budgetCacheKey]*list.Element{}
	imageBudgetCache.bytes = 0
	imageBudgetCache.mu.Unlock()
}

func makeRawPNGChunk(typ string, data []byte) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint32(len(data)))
	out.WriteString(typ)
	out.Write(data)
	sum := crc32.NewIEEE()
	sum.Write([]byte(typ))
	sum.Write(data)
	_ = binary.Write(&out, binary.BigEndian, sum.Sum32())
	return out.Bytes()
}

func makeTestOpaquePNG(w, h int, seed byte, level png.CompressionLevel, extraChunks ...[]byte) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	st := uint32(seed)*747796405 + 2891336453
	for y := range h {
		for x := range w {
			// Smooth diagonal/sinusoidal bands + micro-dither (every 3rd pixel stepped)
			// simulates UI/photographic detail so BestCompression shrinks NoCompression
			// PNG and JPEG Q85 shrinks compressed PNG significantly, without white-noise timeouts.
			st = st*1664525 + 1013904223
			dither := uint8((st >> 28) & 0x0f)
			r := uint8((x*255/max(1, w) + (y/8)*13 + int(seed)*7 + int(dither)) & 0xff)
			g := uint8((y*255/max(1, h) + (x/8)*17 + int(dither>>1)) & 0xff)
			b := uint8(((x+y)*127/max(1, w+h) + ((x^y)/4)*5 + int(dither)) & 0xff)
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: 255})
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: level}
	_ = enc.Encode(&buf, img)
	raw := buf.Bytes()
	if len(extraChunks) == 0 {
		return raw
	}
	var res []byte
	for _, ch := range extraChunks {
		res = append(res, ch...)
	}
	ihdrEnd := 8 + 12 + 13
	var combined bytes.Buffer
	combined.Write(raw[:ihdrEnd])
	combined.Write(res)
	combined.Write(raw[ihdrEnd:])
	return combined.Bytes()
}

func makeTestAlphaPNG(w, h int, level png.CompressionLevel) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	st := uint32(0x13579bdf)
	for y := range h {
		for x := range w {
			st = st*1664525 + 1013904223
			a := uint8(255)
			if x%4 == 0 && y%4 == 0 {
				a = 128
			}
			dither := uint8((st >> 28) & 0x0f)
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8((x*255/max(1, w) + (y/6)*11 + int(dither)) & 0xff),
				G: uint8((y*255/max(1, h) + (x/6)*19 + int(dither)) & 0xff),
				B: uint8(((x ^ y) * 3) + int(dither)),
				A: a,
			})
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: level}
	_ = enc.Encode(&buf, img)
	return buf.Bytes()
}

func makeCorruptCRCPNG(raw []byte) []byte {
	out := bytes.Clone(raw)
	// Corrupt CRC byte inside IEND at tail.
	if len(out) >= 4 {
		out[len(out)-1] ^= 0xff
	}
	return out
}

func makeFakeDimensionPNG(w, h int) []byte {
	base := makeTestOpaquePNG(16, 16, 1, png.DefaultCompression)
	out := bytes.Clone(base)
	binary.BigEndian.PutUint32(out[8+8:8+12], uint32(w))
	binary.BigEndian.PutUint32(out[8+12:8+16], uint32(h))
	crc := crc32.ChecksumIEEE(out[8+4 : 8+8+13])
	binary.BigEndian.PutUint32(out[8+8+13:8+12+13], crc)
	return out
}

func makeInterlacedPNG(w, h int) []byte {
	base := makeTestOpaquePNG(w, h, 3, png.DefaultCompression)
	out := bytes.Clone(base)
	out[8+8+12] = 1 // Adam7 interlaced flag
	crc := crc32.ChecksumIEEE(out[8+4 : 8+8+13])
	binary.BigEndian.PutUint32(out[8+8+13:8+12+13], crc)
	return out
}

func toDataURL(mime string, raw []byte) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(raw)
}

func extractChatDataURLs(t *testing.T, body []byte) []string {
	t.Helper()
	var urls []string
	gjson.GetBytes(body, "messages").ForEach(func(_, m gjson.Result) bool {
		m.Get("content").ForEach(func(_, p gjson.Result) bool {
			if p.Get("type").String() == "image_url" {
				urls = append(urls, p.Get("image_url.url").String())
			}
			return true
		})
		return true
	})
	return urls
}

type budgetMockCopilot struct {
	mu       sync.Mutex
	calls    [][]byte
	paths    []string
	maxBytes int
}

func (m *budgetMockCopilot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.calls = append(m.calls, b)
	m.paths = append(m.paths, r.URL.Path)
	m.mu.Unlock()

	if m.maxBytes > 0 && len(b) > m.maxBytes {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, `{"error":{"message":"Request Entity Too Large","code":"payload_too_large"}}`)
		return
	}
	if r.URL.Path == "/responses" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"resp_ok","object":"response","status":"completed","output":[{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"RESP_OK"}]}],"usage":{"input_tokens":3,"output_tokens":1}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"id":"chat_ok","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"CHAT_OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`)
}

func (m *budgetMockCopilot) asked() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.calls...)
}

func setupBudgetCopilot(t *testing.T, maxBytes int, extraBody provider.ExtraBody) *budgetMockCopilot {
	t.Helper()
	fresh(t)
	resetImageBudgetCacheForTest()

	mock := &budgetMockCopilot{maxBytes: maxBytes}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models":
			io.WriteString(w, `{"data":[`+
				`{"id":"gemini-4-carbon","name":"Gemini 4 Carbon","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gemini-4-neon","name":"Gemini 4 Neon","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gemini-4-hydrogen","name":"Gemini 4 Hydrogen","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gemini-4-argon","name":"Gemini 4 Argon","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gpt-4.1","name":"GPT-4.1","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gemini-5-future","name":"Gemini 5 Future","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}},`+
				`{"id":"gpt-6.2-sol","name":"GPT-6.2-Sol","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/responses"],"capabilities":{"type":"chat","supports":{"reasoning_effort":["low","medium","high"]}}}`+
				`]}`)
		case "/chat/completions", "/responses":
			mock.ServeHTTP(w, r)
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

	if extraBody != nil {
		p, err := provider.Find("copilot")
		if err != nil {
			t.Fatal(err)
		}
		q := *p
		q.ExtraBody = extraBody
		if err := provider.Save(q); err != nil {
			t.Fatal(err)
		}
	}
	return mock
}

func makePaddedChatImageRequest(model, dataURL string, totalBytes int) []byte {
	prefix := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":%q,"detail":"high"}},{"type":"text","text":"`, model, dataURL)
	suffix := `"}]}]}`
	pad := totalBytes - len(prefix) - len(suffix)
	if pad < 0 {
		panic(fmt.Sprintf("payload already exceeds %d bytes (prefix=%d)", totalBytes, len(prefix)))
	}
	return []byte(prefix + strings.Repeat("a", pad) + suffix)
}

func TestForkCopilotChat5MiBBoundaryAllModels(t *testing.T) {
	// Generate uncompressed noisy PNG so lossless stays PNG or Tier 2 converts to small JPEG.
	rawPNG := makeTestOpaquePNG(420, 420, 9, png.NoCompression)
	dataURL := toDataURL("image/png", rawPNG)
	if len(rawPNG) >= copilotChatPerImageMax {
		t.Fatalf("expected rawPNG under perImageMax, got %d", len(rawPNG))
	}

	models := []string{
		"gemini-4-carbon",
		"gemini-4-neon",
		"gemini-4-hydrogen",
		"gemini-4-argon",
		"gpt-4.1",
		"gemini-5-future",
	}
	for _, m := range models {
		t.Run(m, func(t *testing.T) {
			mock := setupBudgetCopilot(t, copilotChatHardCap, nil)
			s := New()

			// Exact 5,242,880 B -> must pass byte-for-byte untouched.
			exact := makePaddedChatImageRequest("copilot/"+m, dataURL, copilotChatHardCap)
			if len(exact) != copilotChatHardCap {
				t.Fatalf("bad exact payload len %d", len(exact))
			}
			// Request rewrites model to upstream name ("copilot/" prefix stripped in upstream wire).
			// Test model name without "copilot/" prefix inside exact wire measurement? Wait: rewriteModel
			// changes "copilot/<m>" -> "<m>" (shrinks 8 bytes)! Let's test both via fitImageBudget AND gateway!
			// For gateway exact byte test, check fitImageBudget directly at 5,242,880 B and 5,242,881 B,
			// AND test gateway with copilot/<m> accounting for "copilot/" removal!
			directExact := makePaddedChatImageRequest(m, dataURL, copilotChatHardCap)
			gotExact, _, ok := fitImageBudget(provider.Chat, directExact, copilotChatHardCap, copilotChatPerImageMax)
			if !ok || !bytes.Equal(gotExact, directExact) {
				t.Fatalf("exact %d B must stay byte-for-byte untouched (ok=%v, gotLen=%d)", copilotChatHardCap, ok, len(gotExact))
			}

			// 5,242,881 B -> must compress and fit <= 5,242,880 B while keeping high-detail metadata.
			// Account for gateway stripping "copilot/" (8 bytes) on the wire by adding 8+1 bytes.
			overWire := makePaddedChatImageRequest("copilot/"+m, dataURL, copilotChatHardCap+len("copilot/")+1)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(overWire))
			req.Header.Set("Content-Type", "application/json")
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("%s failed: %d %s", m, rec.Code, rec.Body.String())
			}
			calls := mock.asked()
			if len(calls) != 1 {
				t.Fatalf("calls = %d, want 1", len(calls))
			}
			if len(calls[0]) > copilotChatHardCap {
				t.Fatalf("sent %d bytes > %d", len(calls[0]), copilotChatHardCap)
			}
			if !strings.Contains(string(calls[0]), `"detail":"high"`) {
				t.Fatalf("detail field lost during compression")
			}

			// Exact 5,242,880 B on the wire via gateway stays untouched byte-for-byte (same PNG dataURL!).
			exactWireReq := makePaddedChatImageRequest("copilot/"+m, dataURL, copilotChatHardCap+len("copilot/"))
			rec2 := httptest.NewRecorder()
			req2 := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(exactWireReq))
			req2.Header.Set("Content-Type", "application/json")
			s.Handler().ServeHTTP(rec2, req2)
			if rec2.Code != 200 {
				t.Fatalf("%s exact failed: %d %s", m, rec2.Code, rec2.Body.String())
			}
			calls = mock.asked()
			if len(calls) != 2 || len(calls[1]) != copilotChatHardCap || !bytes.Contains(calls[1], []byte(dataURL)) {
				t.Fatalf("gateway 5,242,880 B modified unexpectedly (len=%d)", len(calls[1]))
			}
		})
	}
}

func TestForkCopilotResponsesIsolationAndNoPoison(t *testing.T) {
	rawPNG := makeTestOpaquePNG(400, 400, 3, png.NoCompression)
	dataURL := toDataURL("image/png", rawPNG)
	mock := setupBudgetCopilot(t, 0, nil)
	s := New()

	// 1. Copilot /chat/completions learns a smaller 2 MiB body cap.
	s.bodyCaps.learn(bodyCapKey(provider.Provider{ID: "copilot"}, provider.Chat), 2<<20)

	// 2. Copilot /responses (gpt-6.2-sol) with > 5 MiB request MUST remain untouched on the wire.
	prefix := fmt.Sprintf(`{"model":"copilot/gpt-6.2-sol","store":false,"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":%q},{"type":"input_text","text":"`, dataURL)
	suffix := `"}]}]}`
	target := copilotChatHardCap + 300_000
	pad := target - len(prefix) - len(suffix)
	respBody := []byte(prefix + strings.Repeat("r", pad) + suffix)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(respBody))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "RESP_OK") {
		t.Fatalf("/responses failed: %d %s", rec.Code, rec.Body.String())
	}
	calls := mock.asked()
	if len(calls) != 1 || len(calls[0]) <= copilotChatHardCap || !bytes.Contains(calls[0], []byte(dataURL)) {
		t.Fatalf("Copilot /responses was altered or poisoned by /chat/completions cap: len=%d", len(calls[0]))
	}
}

func TestForkExtraBodyPushesOverCapCaughtAndFitted(t *testing.T) {
	fresh(t)
	resetImageBudgetCacheForTest()

	rawPNG := makeTestOpaquePNG(450, 450, 5, png.NoCompression)
	dataURL := toDataURL("image/png", rawPNG)

	var mu sync.Mutex
	var calls [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"CHAT_OK"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)

	const capBytes = 2 << 20 // 2 MiB learned cap -> capNear = 1.8 MiB, capRoom = 1.5 MiB
	extraPad := `"` + strings.Repeat("x", 150_000) + `"`
	if err := provider.Save(provider.Provider{
		ID:        "extrabody",
		Name:      "ExtraBody",
		Key:       "sk-eb",
		Models:    []string{"m1"},
		Chat:      srv.URL + "/v1",
		ExtraBody: provider.ExtraBody{"fork_extra_pad": json.RawMessage(extraPad)},
	}); err != nil {
		t.Fatal(err)
	}

	s := New()
	s.bodyCaps.learn(bodyCapKey(provider.Provider{ID: "extrabody"}, provider.Chat), capBytes)

	// Wire body BEFORE ExtraBody is ~1.72 MiB (< capNear(2 MiB) = 1.8 MiB),
	// so after ExtraBody (+150 KB = ~1.87 MiB > 1.8 MiB) only post-ExtraBody withinCap catches it!
	preExtraTarget := capNear(capBytes) - 80_000
	reqBytes := makePaddedChatImageRequest("extrabody/m1", dataURL, preExtraTarget)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "CHAT_OK") {
		t.Fatalf("extraBody budget fit failed: %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	if len(calls[0]) > capRoom(capBytes) {
		t.Fatalf("wire body exceeded capRoom despite ExtraBody ordering: len=%d capRoom=%d", len(calls[0]), capRoom(capBytes))
	}
	if !strings.Contains(string(calls[0]), `"fork_extra_pad"`) {
		t.Fatalf("ExtraBody field missing from wire body")
	}
}

func TestForkImageBudgetTier1LosslessPNGMetadata(t *testing.T) {
	resetImageBudgetCacheForTest()
	srgb := makeRawPNGChunk("sRGB", []byte{0})
	phys := makeRawPNGChunk("pHYs", []byte{0, 0, 0x0b, 0x13, 0, 0, 0x0b, 0x13, 1})
	cicp := makeRawPNGChunk("cICP", []byte{1, 13, 0, 1})
	idot := makeRawPNGChunk("iDOT", bytes.Repeat([]byte{0xaa}, 4096))
	textJunk := makeRawPNGChunk("tEXt", append([]byte("Comment\x00"), bytes.Repeat([]byte("z"), 40_000)...))

	rawPNG := makeTestOpaquePNG(300, 300, 11, png.NoCompression, srgb, phys, cicp, idot, textJunk)
	body := makePaddedChatImageRequest("gemini-4-carbon", toDataURL("image/png", rawPNG), len(toDataURL("image/png", rawPNG))+2000)
	hardCap := len(body) - 10_000 // Tier 1 lossless alone saves far more than 10 KB

	out, dropped, ok := fitImageBudget(provider.Chat, body, hardCap, 0)
	if !ok || dropped != 0 || len(out) > hardCap {
		t.Fatalf("Tier 1 lossless failed: ok=%v dropped=%d len=%d hardCap=%d", ok, dropped, len(out), hardCap)
	}
	urls := extractChatDataURLs(t, out)
	if len(urls) != 1 || !strings.HasPrefix(urls[0], "data:image/png;base64,") {
		t.Fatalf("expected lossless PNG output, got %q", urls)
	}
	_, b64, _ := parseSupportedDataURL(urls[0])
	decBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	info, err := parsePNGChunks(decBytes)
	if err != nil {
		t.Fatalf("invalid Tier 1 PNG: %v", err)
	}
	has := map[string]bool{}
	for _, ch := range info.chunks {
		has[ch.typ] = true
	}
	if has["iDOT"] || has["tEXt"] {
		t.Fatalf("expected iDOT/tEXt to be stripped, chunks=%v", has)
	}
	for _, want := range []string{"sRGB", "pHYs", "cICP"} {
		if !has[want] {
			t.Fatalf("expected %s chunk preserved, chunks=%v", want, has)
		}
	}
}

func TestForkImageBudgetTier2OpaqueJPEGvsAlphaAndHDRPreserved(t *testing.T) {
	resetImageBudgetCacheForTest()

	// 1. Opaque non-HDR PNG -> JPEG Q85 in Tier 2.
	opaquePNG := makeTestOpaquePNG(500, 500, 22, png.BestCompression)
	req1 := makePaddedChatImageRequest("gemini-4-carbon", toDataURL("image/png", opaquePNG), len(toDataURL("image/png", opaquePNG))+500)
	out1, dropped1, ok1 := fitImageBudget(provider.Chat, req1, len(req1)/2, 0)
	if !ok1 || dropped1 != 0 {
		t.Fatalf("opaque Tier 2 failed: ok=%v dropped=%d", ok1, dropped1)
	}
	urls1 := extractChatDataURLs(t, out1)
	if len(urls1) != 1 || !strings.HasPrefix(urls1[0], "data:image/jpeg;base64,") {
		t.Fatalf("expected opaque PNG -> JPEG, got %q", urls1)
	}
	_, b64, _ := parseSupportedDataURL(urls1[0])
	rawJPEG, _ := base64.StdEncoding.DecodeString(b64)
	if _, err := jpeg.Decode(bytes.NewReader(rawJPEG)); err != nil {
		t.Fatalf("Tier 2 JPEG invalid: %v", err)
	}

	// 2. Alpha PNG & HDR (cICP) PNG -> NEVER converted to JPEG, resize in Tier 3 as PNG!
	makeNoisePNG := func(w, h int, seed uint32, withAlpha bool, extra ...[]byte) []byte {
		im := image.NewNRGBA(image.Rect(0, 0, w, h))
		st := seed
		for y := range h {
			for x := range w {
				st = st*1664525 + 1013904223
				a := uint8(255)
				if withAlpha && x%2 == 0 && y%2 == 0 {
					a = 128
				}
				im.SetNRGBA(x, y, color.NRGBA{
					R: uint8((st >> 24) & 0xff),
					G: uint8((st >> 16) & 0xff),
					B: uint8((st >> 8) & 0xff),
					A: a,
				})
			}
		}
		var b bytes.Buffer
		_ = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&b, im)
		raw := b.Bytes()
		if len(extra) == 0 {
			return raw
		}
		var ex []byte
		for _, ch := range extra {
			ex = append(ex, ch...)
		}
		return bytes.Join([][]byte{raw[:8+12+13], ex, raw[8+12+13:]}, nil)
	}
	alphaPNG := makeNoisePNG(900, 900, 0x13579bdf, true)
	cicp := makeRawPNGChunk("cICP", []byte{9, 16, 0, 1})
	hdrPNG := makeNoisePNG(900, 900, 0x2468ace0, false, cicp)

	req2 := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}},{"type":"image_url","image_url":{"url":%q}}]}]}`,
		toDataURL("image/png", alphaPNG), toDataURL("image/png", hdrPNG)))
	// Force Tier 3 resize (alpha+HDR skip Tier 2).
	out2, dropped2, ok2 := fitImageBudget(provider.Chat, req2, len(req2)*9/10, 0)
	if !ok2 || dropped2 != 0 {
		t.Fatalf("alpha/HDR resize failed: ok=%v dropped=%d", ok2, dropped2)
	}
	for i, u := range extractChatDataURLs(t, out2) {
		if !strings.HasPrefix(u, "data:image/png;base64,") {
			t.Fatalf("image %d converted away from PNG (alpha/HDR violation): %.40s", i, u)
		}
	}
}

func TestForkImageBudgetResizeMinShortSideAndAspectGuard(t *testing.T) {
	if w, h, ok := computeBudgetResizeDims(600, 600, 0.85); ok || w != 0 || h != 0 {
		t.Fatalf("short<=720 should skip resize, got %dx%d ok=%v", w, h, ok)
	}
	if w, h, ok := computeBudgetResizeDims(3200, 800, 0.85); ok || w != 0 || h != 0 {
		t.Fatalf("aspect>3:1 should skip resize, got %dx%d ok=%v", w, h, ok)
	}
	if w, h, ok := computeBudgetResizeDims(800, 800, 0.70); !ok || min(w, h) != 720 {
		t.Fatalf("expected min short side clamped to 720, got %dx%d ok=%v", w, h, ok)
	}
	if w, h, ok := computeBudgetResizeDims(2400, 1600, 0.85); !ok || w != 2040 || h != 1360 {
		t.Fatalf("expected 2040x1360, got %dx%d ok=%v", w, h, ok)
	}
	if w, h, ok := computeBudgetResizeDims(2400, 1600, 0.70); !ok || w != 1680 || h != 1120 {
		t.Fatalf("expected 1680x1120, got %dx%d ok=%v", w, h, ok)
	}
}

func TestForkImageBudgetTier5HistoryDropProtectsCurrentTurn(t *testing.T) {
	resetImageBudgetCacheForTest()
	histShot0 := "data:image/png;base64,HIST0_" + strings.Repeat("Z", 1_500_000)
	histShot1 := "data:image/png;base64,HIST1_" + strings.Repeat("Y", 1_500_000)
	currUserShot := "data:image/png;base64,CURR_USER_" + strings.Repeat("X", 500_000)
	currToolShot := "data:image/png;base64,CURR_TOOL_" + strings.Repeat("W", 500_000)

	body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"text","text":"old turn"},{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"tool","tool_call_id":"t1","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":[{"type":"text","text":"current turn"},{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"assistant","content":"","tool_calls":[{"id":"t2","type":"function","function":{"name":"view","arguments":"{}"}}]},`+
		`{"role":"tool","tool_call_id":"t2","content":[{"type":"image_url","image_url":{"url":%q}}]}`+
		`]}`, histShot0, histShot1, currUserShot, currToolShot))

	out, dropped, ok := fitImageBudget(provider.Chat, body, 1_800_000, 0)
	if !ok || dropped != 2 || len(out) > 1_800_000 {
		t.Fatalf("Tier 5 failed: ok=%v dropped=%d len=%d", ok, dropped, len(out))
	}
	s := string(out)
	if strings.Contains(s, "HIST0_") || strings.Contains(s, "HIST1_") {
		t.Fatalf("expected both history images to be dropped")
	}
	if !strings.Contains(s, "CURR_USER_") || !strings.Contains(s, "CURR_TOOL_") {
		t.Fatalf("protected current-turn images (user + trailing tool) must remain")
	}
	if strings.Count(s, imageLeftOut) != 2 {
		t.Fatalf("expected 2 imageLeftOut placeholders, got %d", strings.Count(s, imageLeftOut))
	}
}

func TestForkImageBudgetStepwiseRollback(t *testing.T) {
	resetImageBudgetCacheForTest()

	// Smooth multi-tone texture (like a UI gradient / screenshot without white-noise dithering)
	// compresses moderately in PNG (~250 KB) and shrinks dramatically in JPEG Q85 (~30 KB).
	photoImg := image.NewNRGBA(image.Rect(0, 0, 760, 760))
	for y := range 760 {
		for x := range 760 {
			r := uint8(((x * 255 / 760) + (y/16)*19 + ((x ^ y) & 0x1f)) & 0xff)
			g := uint8(((y * 255 / 760) + (x/16)*23 + (((x + y) >> 1) & 0x1f)) & 0xff)
			b := uint8((((x + y) * 127 / 760) + ((x * y) >> 8)) & 0xff)
			photoImg.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: 255})
		}
	}
	var hBuf bytes.Buffer
	_ = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&hBuf, photoImg)
	// Add 120 KB compressible text chunk so Tier 1 strips it cleanly, while Tier 2 JPEG saves ~150+ KB more.
	histJunk := makeRawPNGChunk("tEXt", append([]byte("History\x00"), bytes.Repeat([]byte("h"), 120_000)...))
	histPNG := bytes.Join([][]byte{hBuf.Bytes()[:8+12+13], histJunk, hBuf.Bytes()[8+12+13:]}, nil)

	protJunk := makeRawPNGChunk("tEXt", append([]byte("Comment\x00"), bytes.Repeat([]byte("k"), 30_000)...))
	protPNG := makeTestOpaquePNG(240, 240, 42, png.BestCompression, protJunk) // Tier 1 strips ~30 KB

	histURL := toDataURL("image/png", histPNG)
	protURL := toDataURL("image/png", protPNG)
	body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":[{"type":"text","text":"keep me sharp"},{"type":"image_url","image_url":{"url":%q}}]}`+
		`]}`, histURL, protURL))

	histDummy := &budgetImage{kind: imgKindDataURL, origMIME: "image/png", origB64: strings.SplitN(histURL, ",", 2)[1], hash: sha256.Sum256([]byte(histURL))}
	protDummy := &budgetImage{kind: imgKindDataURL, origMIME: "image/png", origB64: strings.SplitN(protURL, ",", 2)[1], hash: sha256.Sum256([]byte(protURL))}
	t1Hist, _, okHist := encodeTierCandidate(histDummy, 1, nil)
	t1Prot, _, okProt := encodeTierCandidate(protDummy, 1, nil)
	t2Hist, _, okHistT2 := encodeTierCandidate(histDummy, 2, nil)
	if !okHist || !okProt || !okHistT2 {
		t.Fatalf("expected Tier 1/2 improvements on fixtures (okHist=%v okProt=%v okHistT2=%v)", okHist, okProt, okHistT2)
	}
	wireLen := func(mime string, raw []byte) int {
		return len(jsonStringLiteral("data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(raw)))
	}
	overhead := len(body) - (len(histURL) + len(protURL) + 4)
	afterT1Len := overhead + wireLen("image/png", t1Hist) + wireLen("image/png", t1Prot)
	afterT2WithOrigProt := overhead + wireLen("image/jpeg", t2Hist) + (len(protURL) + 2)
	if afterT2WithOrigProt >= afterT1Len {
		t.Fatalf("fixture assumptions violated: afterT2WithOrigProt=%d >= afterT1Len=%d", afterT2WithOrigProt, afterT1Len)
	}
	// Target 100 bytes below afterT1Len -> Tier 1 alone cannot meet hardCap, so Tier 2 runs on hist
	// and creates enough headroom for stepwise rollback to revert prot back to original!
	hardCap := afterT1Len - 100

	out, dropped, ok := fitImageBudget(provider.Chat, body, hardCap, 0)
	if !ok || dropped != 0 || len(out) > hardCap {
		t.Fatalf("rollback scenario failed: ok=%v dropped=%d len=%d hardCap=%d", ok, dropped, len(out), hardCap)
	}
	urls := extractChatDataURLs(t, out)
	if len(urls) != 2 {
		t.Fatalf("expected 2 images preserved, got %d", len(urls))
	}
	if !strings.HasPrefix(urls[0], "data:image/jpeg;base64,") {
		t.Fatalf("expected hist compressed to JPEG, got %.40s", urls[0])
	}
	if urls[1] != protURL {
		t.Fatalf("expected stepwise rollback to revert unnecessary Tier 1 on protected image")
	}
}

func TestForkImageBudgetLRUCacheAndPerImageCap(t *testing.T) {
	resetImageBudgetCacheForTest()

	// 1030x1030 NoCompression 3-byte RGB PNG is ~3.18 MB raw (> 3 MiB copilotChatPerImageMax),
	// while its base64 JSON is ~4.25 MB (< 5 MiB total body cap).
	bigRawPNG := makeTestOpaquePNG(1030, 1030, 77, png.NoCompression)
	if len(bigRawPNG) <= copilotChatPerImageMax {
		t.Fatalf("fixture should exceed 3 MiB raw, got %d", len(bigRawPNG))
	}
	dataURL := toDataURL("image/png", bigRawPNG)
	body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]}]}`, dataURL))
	if len(body) > copilotChatHardCap {
		t.Fatalf("fixture body=%d should be under 5 MiB to specifically test perImageMax trigger", len(body))
	}

	out1, dropped1, ok1 := fitImageBudget(provider.Chat, body, copilotChatHardCap, copilotChatPerImageMax)
	if !ok1 || dropped1 != 0 {
		t.Fatalf("perImageMax fit failed: ok=%v dropped=%d", ok1, dropped1)
	}
	urls1 := extractChatDataURLs(t, out1)
	if len(urls1) != 1 {
		t.Fatalf("expected 1 image, got %d", len(urls1))
	}
	_, b64, _ := parseSupportedDataURL(urls1[0])
	rawOut, _ := base64.StdEncoding.DecodeString(b64)
	if len(rawOut) > copilotChatPerImageMax {
		t.Fatalf("re-encoded image still exceeds 3 MiB perImageMax: %d", len(rawOut))
	}

	// Second identical request hits LRU cache and yields byte-identical JSON for prefix caching.
	out2, dropped2, ok2 := fitImageBudget(provider.Chat, body, copilotChatHardCap, copilotChatPerImageMax)
	if !ok2 || dropped2 != 0 || !bytes.Equal(out1, out2) {
		t.Fatalf("cache hit produced non-identical output (ok=%v dropped=%d eq=%v)", ok2, dropped2, bytes.Equal(out1, out2))
	}
}

func TestForkImageBudgetSafetyGuards(t *testing.T) {
	resetImageBudgetCacheForTest()

	validPNG := makeTestOpaquePNG(300, 300, 1, png.DefaultCompression)
	badCRC := toDataURL("image/png", makeCorruptCRCPNG(validPNG))
	interlaced := toDataURL("image/png", makeInterlacedPNG(300, 300))
	bomb := toDataURL("image/png", makeFakeDimensionPNG(10000, 10000))
	actlChunk := makeRawPNGChunk("acTL", []byte{0, 0, 0, 2, 0, 0, 0, 0})
	animated := toDataURL("image/png", makeTestOpaquePNG(64, 64, 2, png.DefaultCompression, actlChunk))
	corrupt := "data:image/png;base64,NOT_VALID_BASE64!!!"

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"bad_crc", badCRC},
		{"interlaced", interlaced},
		{"decompression_bomb", bomb},
		{"animated", animated},
		{"corrupt_b64", corrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var used int64
			body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]}]}`, tc.url))
			// Latest user message protected -> Tiers 1..4 must skip cleanly without panicking, Tier 5 cannot drop -> ok=false, body untouched.
			out, dropped, ok := fitImageBudget(provider.Chat, body, len(body)-100, 0)
			_ = used
			if ok || dropped != 0 || !bytes.Equal(out, body) {
				t.Fatalf("%s unexpectedly modified or crashed: ok=%v dropped=%d", tc.name, ok, dropped)
			}
		})
	}
}

func TestForkRefitOverCapSingle075StepWhenNoStatedSize(t *testing.T) {
	fresh(t)
	resetImageBudgetCacheForTest()

	// Build a 6 MB session of uncompressible fake 1 MB screenshots in history + latest user screenshot.
	var sb strings.Builder
	sb.WriteString(`{"model":"fake/m1","messages":[`)
	for i := range 5 {
		fmt.Fprintf(&sb, `{"role":"user","content":[{"type":"text","text":"h%d"},{"type":"image_url","image_url":{"url":"data:image/png;base64,FAKE%02d%s"}}]},`, i, i, strings.Repeat("A", 1_000_000))
	}
	fmt.Fprintf(&sb, `{"role":"user","content":[{"type":"text","text":"latest"},{"type":"image_url","image_url":{"url":"data:image/png;base64,LAST%s"}}]}]}`, strings.Repeat("B", 1_000_000))
	reqBody := sb.String()

	var mu sync.Mutex
	var calls [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, b)
		n := len(calls)
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			io.WriteString(w, `{"error":{"message":"Request body is too large"}}`) // NO stated size!
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)

	if err := provider.Save(provider.Provider{
		ID: "fake", Name: "Fake", Key: "sk", Models: []string{"m1"}, Chat: srv.URL + "/v1",
	}); err != nil {
		t.Fatal(err)
	}

	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "OK") {
		t.Fatalf("refit failed: %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	sent0, sent1 := len(calls[0]), len(calls[1])
	// Single 0.75x step from ~6 MB drops 2 oldest screenshots (~4 MB), whereas double 0.75x (0.5625x = ~3.375 MB)
	// would drop 3 screenshots (~3 MB). Verify sent1 > sent0*60/100 and sent1 <= capRoom(sent0).
	if sent1 > capRoom(sent0) || sent1 <= sent0*60/100 {
		t.Fatalf("expected single 0.75x refit step: sent0=%d sent1=%d capRoom=%d", sent0, sent1, capRoom(sent0))
	}
}

func TestForkCopilotChat5MiBHysteresisAndMultiTurnPrefixCache(t *testing.T) {
	mock := setupBudgetCopilot(t, copilotChatHardCap, nil)
	s := New()

	// Two ~2.13 MB PNG data URLs (730x730 NoCompression -> ~1.60 MB raw each).
	img0URL := toDataURL("image/png", makeTestOpaquePNG(730, 730, 13, png.NoCompression))
	img1URL := toDataURL("image/png", makeTestOpaquePNG(730, 730, 29, png.NoCompression))

	m0 := fmt.Sprintf(`{"role":"user","content":[{"type":"text","text":"oldest shot"},{"type":"image_url","image_url":{"url":%q,"detail":"high"}}]}`, img0URL)
	a0 := `{"role":"assistant","content":"noted shot 0"}`
	m1 := fmt.Sprintf(`{"role":"user","content":[{"type":"text","text":"newer shot"},{"type":"image_url","image_url":{"url":%q}}]}`, img1URL)
	a1 := `{"role":"assistant","content":"noted shot 1"}`

	postTurn := func(msgs ...string) {
		t.Helper()
		reqBody := fmt.Sprintf(`{"model":"copilot/gemini-4-carbon","messages":[%s]}`, strings.Join(msgs, ","))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Magpie-Session", "sess-hysteresis-1")
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("gateway turn failed: %d %s", rec.Code, rec.Body.String())
		}
	}

	// Turn 1: single image < 5 MiB -> untouched byte-for-byte.
	postTurn(m0)

	// Turn 2: crosses 5 MiB (> 5,242,880 B) -> tail-first compresses M1 down under 4.0 MiB (softTarget),
	// leaving older M0 untouched byte-for-byte.
	turn2Text := fmt.Sprintf(`{"role":"user","content":%q}`, "turn2 "+strings.Repeat("b", 1_150_000))
	postTurn(m0, a0, m1, a1, turn2Text)

	// Turns 3..5: each adds +150 KB pure text (raw request stays > 5 MiB, sticky M1 keeps wire < 5 MiB).
	msgs := []string{m0, a0, m1, a1, turn2Text, `{"role":"assistant","content":"ok 2"}`}
	for turn := 3; turn <= 5; turn++ {
		msgs = append(msgs,
			fmt.Sprintf(`{"role":"user","content":%q}`, fmt.Sprintf("turn%d %s", turn, strings.Repeat("c", 150_000))),
			fmt.Sprintf(`{"role":"assistant","content":"ok %d"}`, turn),
		)
		postTurn(msgs[:len(msgs)-1]...)
	}

	calls := mock.asked()
	if len(calls) != 5 {
		t.Fatalf("calls = %d, want 5", len(calls))
	}
	if !bytes.Contains(calls[0], []byte(img0URL)) {
		t.Fatalf("Turn 1 (< 5 MiB) modified img0 unexpectedly")
	}
	if len(calls[1]) > copilotChatSoftCap {
		t.Fatalf("Turn 2 expected hysteresis fit <= %d (softTarget), got %d", copilotChatSoftCap, len(calls[1]))
	}
	if !bytes.Contains(calls[1], []byte(img0URL)) {
		t.Fatalf("Turn 2 touched oldest cached img0 instead of compressing newer history img1 first")
	}
	m2OnTurn2 := gjson.GetBytes(calls[1], "messages.2").Raw
	if !strings.Contains(m2OnTurn2, "data:image/jpeg;base64,") {
		t.Fatalf("expected newer history img1 compressed to JPEG on Turn 2, got %.80s", m2OnTurn2)
	}

	m0OnTurn2 := gjson.GetBytes(calls[1], "messages.0").Raw
	for i := 2; i < len(calls); i++ {
		if len(calls[i]) > copilotChatHardCap {
			t.Fatalf("Turn %d exceeded 5 MiB hardCap: %d", i+1, len(calls[i]))
		}
		if gjson.GetBytes(calls[i], "messages.0").Raw != m0OnTurn2 {
			t.Fatalf("Turn %d broke prefix at messages[0]", i+1)
		}
		if gjson.GetBytes(calls[i], "messages.2").Raw != m2OnTurn2 {
			t.Fatalf("Turn %d drifted/bounced messages[2] away from Turn 2 sticky wire bytes", i+1)
		}
	}
}

func TestForkImageBudgetStickyFloorPreventsRollbackFlip(t *testing.T) {
	resetImageBudgetCacheForTest()

	// img0: smooth PNG + text chunk (Tier 1 strips text chunk, Tier 2 JPEG shrinks much smaller).
	// img1: large uncompressed gradient PNG (Tier 2 JPEG shrinks by > 1.5 MB).
	img0Raw := makeTestOpaquePNG(500, 500, 19, png.NoCompression,
		makeRawPNGChunk("tEXt", append([]byte("Meta\x00"), bytes.Repeat([]byte("m"), 40_000)...)))
	img0URL := toDataURL("image/png", img0Raw)
	img1URL := toDataURL("image/png", makeTestOpaquePNG(1200, 1200, 23, png.NoCompression))

	body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":"latest question"}`+
		`]}`, img0URL, img1URL))

	imgs := collectBudgetImages(provider.Chat, body)
	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d", len(imgs))
	}
	// Simulate img0 already sticky at Tier 2 (JPEG). Compute img0/img1 Tier 2 wire sizes so total
	// starts above triggerCap before img1 compresses, yet after img1 -> T2 leaves > len(img0URL) room.
	t2Img0, _, ok0 := encodeTierCandidate(&imgs[0], 2, nil)
	t2Img1, _, ok1 := encodeTierCandidate(&imgs[1], 2, nil)
	if !ok0 || !ok1 {
		t.Fatalf("fixture encode failed (ok0=%v ok1=%v)", ok0, ok1)
	}
	afterStickyOnlyLen := len(body) + makeCompressedSnapshot(&imgs[0], 2, t2Img0, "image/jpeg").delta
	afterBothT2Len := afterStickyOnlyLen + makeCompressedSnapshot(&imgs[1], 2, t2Img1, "image/jpeg").delta

	opts := budgetFitOptions{
		hardCap:     afterStickyOnlyLen - 10_000,
		triggerCap:  afterStickyOnlyLen - 10_000,
		softTarget:  afterStickyOnlyLen - 10_000,
		protTarget:  afterStickyOnlyLen - 10_000,
		dropTrigger: afterStickyOnlyLen - 10_000,
		stickyTier: func(msgIdx int, hash [sha256.Size]byte) int {
			if msgIdx == 0 && hash == imgs[0].hash {
				return 2
			}
			return 0
		},
	}
	if opts.softTarget-afterBothT2Len <= len(img0URL)-len(t2Img0) {
		t.Fatalf("expected sufficient slack after img1->T2 so only floorVer prevents img0 rollback (slack=%d)", opts.softTarget-afterBothT2Len)
	}

	out, dropped, updates, ok := fitImageBudgetWithOptions(provider.Chat, body, opts)
	if !ok || dropped != 0 || len(out) > opts.hardCap {
		t.Fatalf("fit failed: ok=%v dropped=%d len=%d hardCap=%d", ok, dropped, len(out), opts.hardCap)
	}
	urls := extractChatDataURLs(t, out)
	if len(urls) != 2 {
		t.Fatalf("expected 2 images, got %d", len(urls))
	}
	if !strings.HasPrefix(urls[0], "data:image/jpeg;base64,") {
		t.Fatalf("sticky Tier 2 on img0 bounced back! got %.50s", urls[0])
	}
	var gotTier0 int
	for _, u := range updates {
		if u.msgIdx == 0 {
			gotTier0 = u.tier
		}
	}
	if gotTier0 < 2 {
		t.Fatalf("expected sticky update tier >= 2 for img0, got %d", gotTier0)
	}
}

func TestForkImageBudgetStickyIsolationAndFailedAttemptNoPoison(t *testing.T) {
	fresh(t)
	resetImageBudgetCacheForTest()

	imgURL := toDataURL("image/png", makeTestOpaquePNG(640, 640, 37, png.NoCompression))

	var mu sync.Mutex
	var failNext bool
	var calls [][]byte
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models":
			io.WriteString(w, `{"data":[{"id":"gemini-4-carbon","name":"Gemini 4 Carbon","model_picker_enabled":true,"policy":{"state":"enabled"},"supported_endpoints":["/chat/completions"],"capabilities":{"type":"chat","supports":{}}}]}`)
		case "/chat/completions":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			calls = append(calls, b)
			fail := failNext
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"error":{"message":"upstream hiccup"}}`)
				return
			}
			io.WriteString(w, `{"id":"chat_ok","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
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
			json.NewEncoder(w).Encode(map[string]any{"token": "sess", "expires_at": time.Now().Add(time.Hour).Unix(), "endpoints": map[string]string{"api": api.URL}})
			return
		}
		io.WriteString(w, `{"copilot_plan":"individual"}`)
	}))
	t.Cleanup(gh.Close)
	oldTok, oldUser := provider.CopilotTokenURL, provider.CopilotUserURL
	provider.CopilotTokenURL, provider.CopilotUserURL = gh.URL+"/token", gh.URL+"/user"
	t.Cleanup(func() { provider.CopilotTokenURL, provider.CopilotUserURL = oldTok, oldUser })

	s := New()
	send := func(sess string, body []byte) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Magpie-Session", sess)
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	lastCall := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return calls[len(calls)-1]
	}

	// 1. Failing upstream (HTTP 500, even across retries) on > 5 MiB request MUST NOT commit sticky tier.
	mu.Lock()
	failNext = true
	mu.Unlock()
	overBody := []byte(fmt.Sprintf(`{"model":"copilot/gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":%q}]}`, imgURL, strings.Repeat("p", copilotChatHardCap-len(imgURL)+200_000)))
	if code := send("sess-fail", overBody); code != 500 {
		t.Fatalf("expected 500, got %d", code)
	}

	mu.Lock()
	failNext = false
	mu.Unlock()
	underSameSess := []byte(fmt.Sprintf(`{"model":"copilot/gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":"small follow-up"}]}`, imgURL))
	if code := send("sess-fail", underSameSess); code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if !bytes.Contains(lastCall(), []byte(imgURL)) {
		t.Fatalf("failed HTTP 500 turn poisoned sticky state for sess-fail")
	}

	// 2. Successful > 5 MiB request on sess-a commits sticky tier on msgIdx=0;
	// sess-b sending same imgURL < 5 MiB MUST remain untouched;
	// sess-a re-pasting same imgURL at msgIdx=2 keeps msgIdx=0 sticky and msgIdx=2 original!
	if code := send("sess-a", overBody); code != 200 {
		t.Fatalf("expected 200 for sess-a overBody, got %d", code)
	}
	if code := send("sess-b", underSameSess); code != 200 {
		t.Fatalf("expected 200 for sess-b, got %d", code)
	}
	sessBCall := lastCall()
	repasted := []byte(fmt.Sprintf(`{"model":"copilot/gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"assistant","content":"ack"},`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]}]}`, imgURL, imgURL))
	if code := send("sess-a", repasted); code != 200 {
		t.Fatalf("expected 200 for sess-a repasted, got %d", code)
	}
	sessARepasteCall := lastCall()

	if !bytes.Contains(sessBCall, []byte(imgURL)) {
		t.Fatalf("sess-a sticky tier leaked to sess-b")
	}
	urls := extractChatDataURLs(t, sessARepasteCall)
	if len(urls) != 2 {
		t.Fatalf("expected 2 images in repaste call, got %d", len(urls))
	}
	if urls[0] == imgURL {
		t.Fatalf("expected sess-a msgIdx=0 to stay sticky compressed")
	}
	if urls[1] != imgURL {
		t.Fatalf("expected newly pasted sess-a msgIdx=2 to start fresh uncompressed")
	}
}

func TestForkImageBudgetSoftTargetUnreachableStillMeetsHardCap(t *testing.T) {
	resetImageBudgetCacheForTest()

	imgURL := toDataURL("image/png", makeTestOpaquePNG(520, 520, 17, png.NoCompression))
	// 4.35 MiB of uncompressible text + ~1.08 MiB PNG -> ~5.43 MiB (> 5.0 MiB hardCap).
	// Compressing image drops total to ~4.39 MiB: still > 4.0 MiB softTarget, but <= 5.0 MiB hardCap!
	hugeText := strings.Repeat("t", 4_550_000)
	body := []byte(fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":%q}]}`, imgURL, hugeText))

	out, dropped, _, ok := fitImageBudgetWithOptions(provider.Chat, body, budgetFitOptions{
		hardCap:     copilotChatHardCap,
		triggerCap:  copilotChatHardCap,
		softTarget:  copilotChatSoftCap,
		protTarget:  copilotChatHardCap,
		dropTrigger: copilotChatHardCap,
		perImageMax: copilotChatPerImageMax,
	})
	if !ok {
		t.Fatalf("expected ok=true when total <= hardCap despite exceeding softTarget")
	}
	if dropped != 0 {
		t.Fatalf("expected dropped=0 (no Tier 5 drop once <= hardCap), got %d", dropped)
	}
	if len(out) > copilotChatHardCap || len(out) <= copilotChatSoftCap {
		t.Fatalf("unexpected len(out)=%d (want between %d and %d)", len(out), copilotChatSoftCap, copilotChatHardCap)
	}
}

func TestForkImageBudgetProtectedLosslessBeforeHistoryTouch(t *testing.T) {
	resetImageBudgetCacheForTest()

	histURL := toDataURL("image/png", makeTestOpaquePNG(450, 450, 31, png.BestCompression))
	protJunk := makeRawPNGChunk("tEXt", append([]byte("Comment\x00"), bytes.Repeat([]byte("z"), 1_150_000)...))
	protURL := toDataURL("image/png", makeTestOpaquePNG(240, 240, 41, png.BestCompression, protJunk))

	// Construct body right above 5 MiB so stripping prot's metadata chunk alone brings it <= 4.0 MiB softTarget.
	prefix := fmt.Sprintf(`{"model":"gemini-4-carbon","messages":[`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}}]},`+
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":%q}},{"type":"text","text":"`, histURL, protURL)
	suffix := `"}]}]}`
	pad := (copilotChatHardCap + 50_000) - len(prefix) - len(suffix)
	if pad < 0 {
		t.Fatalf("unexpected negative pad %d", pad)
	}
	body := []byte(prefix + strings.Repeat("w", pad) + suffix)

	out, dropped, _, ok := fitImageBudgetWithOptions(provider.Chat, body, budgetFitOptions{
		hardCap:     copilotChatHardCap,
		triggerCap:  copilotChatHardCap,
		softTarget:  copilotChatSoftCap,
		protTarget:  copilotChatHardCap,
		dropTrigger: copilotChatHardCap,
		perImageMax: copilotChatPerImageMax,
	})
	if !ok || dropped != 0 || len(out) > copilotChatSoftCap {
		t.Fatalf("Pass 0 protected lossless failed: ok=%v dropped=%d len=%d softCap=%d", ok, dropped, len(out), copilotChatSoftCap)
	}
	urls := extractChatDataURLs(t, out)
	if len(urls) != 2 {
		t.Fatalf("expected 2 images, got %d", len(urls))
	}
	if urls[0] != histURL {
		t.Fatalf("Pass 0 should leave cached history image untouched when protected Tier 1 reaches softTarget")
	}
	if !strings.HasPrefix(urls[1], "data:image/png;base64,") {
		t.Fatalf("expected protected image to remain lossless PNG, got %.40s", urls[1])
	}
}
