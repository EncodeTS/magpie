package gateway

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"image"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/yetone/magpie/internal/provider"
)

const (
	copilotChatHardCap     = 5 * 1024 * 1024          // 5,242,880 B empirical GHCP /chat/completions UTF-8 JSON limit
	copilotChatSoftCap     = copilotChatHardCap * 4 / 5 // 4,194,304 B (80%) hysteresis target leaving ~1 MiB text room
	copilotChatPerImageMax = 3 * 1024 * 1024          // 3 MiB per-image cap
	copilotAutoReserve     = 256                      // room for copilot_auto model rewrite

	budgetDeadline     = 3 * time.Second
	budgetCacheMaxByte = 64 << 20
	budgetCacheTTL     = 30 * time.Minute

	stickyTierMaxEntries = 4096
	stickyTierTTL        = 2 * time.Hour
)

// knownBodyCap returns any built-in endpoint-wide request-body limit and per-image
// decoded-byte limit that apply before sending to (p, to). Currently enforces
// GitHub Copilot's 5 MiB limit across all /chat/completions models while leaving
// Copilot /responses (e.g. gpt-6.2-sol) untouched.
func knownBodyCap(p provider.Provider, to provider.Protocol, body []byte) (hardCap int, perImageMax int) {
	if accountAgent(p) == "copilot" && to == provider.Chat {
		hardCap = copilotChatHardCap
		if modelOf(body) == provider.CopilotAuto {
			hardCap -= copilotAutoReserve
		}
		return hardCap, copilotChatPerImageMax
	}
	return 0, 0
}

type budgetCacheKey struct {
	sum  [sha256.Size]byte
	spec string
}

type budgetCacheValue struct {
	mime string
	raw  []byte
	at   time.Time
}

type budgetCacheEntry struct {
	key budgetCacheKey
	val budgetCacheValue
}

var imageBudgetCache = struct {
	mu    sync.Mutex
	ll    *list.List
	m     map[budgetCacheKey]*list.Element
	bytes int64
}{
	m: map[budgetCacheKey]*list.Element{},
}

func budgetCacheGet(sum [sha256.Size]byte, spec string) ([]byte, string, bool) {
	key := budgetCacheKey{sum: sum, spec: spec}
	now := time.Now()
	imageBudgetCache.mu.Lock()
	defer imageBudgetCache.mu.Unlock()
	if imageBudgetCache.ll == nil {
		return nil, "", false
	}
	el, ok := imageBudgetCache.m[key]
	if !ok {
		return nil, "", false
	}
	ent := el.Value.(*budgetCacheEntry)
	if now.Sub(ent.val.at) > budgetCacheTTL {
		imageBudgetCache.bytes -= int64(len(ent.val.raw))
		imageBudgetCache.ll.Remove(el)
		delete(imageBudgetCache.m, key)
		return nil, "", false
	}
	imageBudgetCache.ll.MoveToFront(el)
	return ent.val.raw, ent.val.mime, true
}

func budgetCachePut(sum [sha256.Size]byte, spec string, raw []byte, mime string) {
	if len(raw) == 0 || int64(len(raw)) > budgetCacheMaxByte/4 {
		return
	}
	key := budgetCacheKey{sum: sum, spec: spec}
	now := time.Now()
	cloned := bytes.Clone(raw)

	imageBudgetCache.mu.Lock()
	defer imageBudgetCache.mu.Unlock()
	if imageBudgetCache.ll == nil {
		imageBudgetCache.ll = list.New()
	}
	if el, ok := imageBudgetCache.m[key]; ok {
		ent := el.Value.(*budgetCacheEntry)
		imageBudgetCache.bytes -= int64(len(ent.val.raw))
		ent.val = budgetCacheValue{mime: mime, raw: cloned, at: now}
		imageBudgetCache.bytes += int64(len(cloned))
		imageBudgetCache.ll.MoveToFront(el)
	} else {
		ent := &budgetCacheEntry{key: key, val: budgetCacheValue{mime: mime, raw: cloned, at: now}}
		el := imageBudgetCache.ll.PushFront(ent)
		imageBudgetCache.m[key] = el
		imageBudgetCache.bytes += int64(len(cloned))
	}
	for imageBudgetCache.bytes > budgetCacheMaxByte {
		back := imageBudgetCache.ll.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*budgetCacheEntry)
		imageBudgetCache.bytes -= int64(len(ent.val.raw))
		imageBudgetCache.ll.Remove(back)
		delete(imageBudgetCache.m, ent.key)
	}
}

type stickyConvKey struct {
	providerID string
	to         provider.Protocol
	convKey    string
}

type stickyTierKey struct {
	providerID string
	to         provider.Protocol
	convKey    string
	msgIdx     int
	hash       [sha256.Size]byte
}

type stickyTierEntry struct {
	key  stickyTierKey
	tier int
	at   time.Time
}

type stickyTierUpdate struct {
	msgIdx int
	hash   [sha256.Size]byte
	tier   int
}

// imageStickyStore tracks the highest compression/drop tier committed for each
// (provider, protocol, conversation, message index, image hash) across successful turns.
type imageStickyStore struct {
	mu        sync.Mutex
	ll        *list.List
	m         map[stickyTierKey]*list.Element
	convCount map[stickyConvKey]int
}

func imageStickyConvKey(conv provider.Conversation) string {
	if conv.Subagent != "" {
		return conv.Session + "|" + conv.Subagent
	}
	return conv.Session
}

func (st *imageStickyStore) removeLocked(el *list.Element) {
	ent := el.Value.(*stickyTierEntry)
	st.ll.Remove(el)
	delete(st.m, ent.key)
	ck := stickyConvKey{providerID: ent.key.providerID, to: ent.key.to, convKey: ent.key.convKey}
	if n := st.convCount[ck]; n <= 1 {
		delete(st.convCount, ck)
	} else {
		st.convCount[ck] = n - 1
	}
}

func (st *imageStickyStore) hasConv(providerID string, to provider.Protocol, convKey string) bool {
	if convKey == "" {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.convCount) == 0 {
		return false
	}
	return st.convCount[stickyConvKey{providerID: providerID, to: to, convKey: convKey}] > 0
}

func (st *imageStickyStore) get(providerID string, to provider.Protocol, convKey string, msgIdx int, hash [sha256.Size]byte) int {
	if convKey == "" || hash == ([sha256.Size]byte{}) {
		return 0
	}
	k := stickyTierKey{
		providerID: providerID,
		to:         to,
		convKey:    convKey,
		msgIdx:     msgIdx,
		hash:       hash,
	}
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.ll == nil {
		return 0
	}
	el, ok := st.m[k]
	if !ok {
		return 0
	}
	ent := el.Value.(*stickyTierEntry)
	if now.Sub(ent.at) > stickyTierTTL {
		st.removeLocked(el)
		return 0
	}
	ent.at = now
	st.ll.MoveToFront(el)
	return ent.tier
}

func (st *imageStickyStore) commit(providerID string, to provider.Protocol, convKey string, updates []stickyTierUpdate) {
	if convKey == "" || len(updates) == 0 {
		return
	}
	ck := stickyConvKey{providerID: providerID, to: to, convKey: convKey}
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.ll == nil {
		st.ll = list.New()
		st.m = map[stickyTierKey]*list.Element{}
		st.convCount = map[stickyConvKey]int{}
	}
	for _, u := range updates {
		if u.tier <= 0 || u.hash == ([sha256.Size]byte{}) {
			continue
		}
		k := stickyTierKey{
			providerID: providerID,
			to:         to,
			convKey:    convKey,
			msgIdx:     u.msgIdx,
			hash:       u.hash,
		}
		if el, ok := st.m[k]; ok {
			ent := el.Value.(*stickyTierEntry)
			if now.Sub(ent.at) > stickyTierTTL || u.tier > ent.tier {
				ent.tier = u.tier
			}
			ent.at = now
			st.ll.MoveToFront(el)
			continue
		}
		ent := &stickyTierEntry{key: k, tier: u.tier, at: now}
		el := st.ll.PushFront(ent)
		st.m[k] = el
		st.convCount[ck]++
		for st.ll.Len() > stickyTierMaxEntries {
			back := st.ll.Back()
			if back == nil {
				break
			}
			st.removeLocked(back)
		}
	}
}

type budgetFitOptions struct {
	hardCap     int
	triggerCap  int
	softTarget  int
	protTarget  int
	dropTrigger int
	perImageMax int
	stickyTier  func(msgIdx int, hash [sha256.Size]byte) int
}

type byteEdit struct {
	at, end int
	text    string
}

type budgetImageKind int

const (
	imgKindDataURL budgetImageKind = iota
	imgKindSplitFields
	imgKindDropOnly
)

type budgetImage struct {
	msgIdx      int
	isProtected bool
	kind        budgetImageKind

	partAt, partEnd int
	dropText        string

	// imgKindDataURL edits urlAt..urlEnd as one JSON string `"data:<mime>;base64,<b64>"`
	urlAt, urlEnd int
	// imgKindSplitFields edits mimeAt..mimeEnd and dataAt..dataEnd separately
	mimeAt, mimeEnd int
	dataAt, dataEnd int

	origMIME string
	origB64  string
	hash     [sha256.Size]byte

	// Lazy decoded fields (per invocation, single goroutine)
	origLoaded bool
	origRaw    []byte
	decLoaded  bool
	decImg     image.Image
	decFmt     string
	pngMeta    *pngInfo
	opaque     *bool
	unusable   bool
}

func (im *budgetImage) approxRawBytes() int {
	if im.kind == imgKindDropOnly || len(im.origB64) == 0 {
		return 0
	}
	return len(im.origB64) * 3 / 4
}

func (im *budgetImage) origWireLen() int {
	switch im.kind {
	case imgKindDataURL:
		return im.urlEnd - im.urlAt
	case imgKindSplitFields:
		return (im.mimeEnd - im.mimeAt) + (im.dataEnd - im.dataAt)
	default:
		return im.partEnd - im.partAt
	}
}

func (im *budgetImage) ensureOrig() bool {
	if im.origLoaded {
		return len(im.origRaw) > 0
	}
	im.origLoaded = true
	if im.kind == imgKindDropOnly || im.origB64 == "" {
		im.unusable = true
		return false
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, im.origB64)
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil || len(raw) == 0 {
		im.unusable = true
		return false
	}
	im.origRaw = raw
	return true
}

func (im *budgetImage) ensureDecoded(decodeUsed *int64) bool {
	if im.unusable {
		return false
	}
	if im.decLoaded {
		return im.decImg != nil
	}
	im.decLoaded = true
	if !im.ensureOrig() {
		return false
	}
	if im.origMIME == "image/png" {
		info, err := parsePNGChunks(im.origRaw)
		if err != nil || info.animated || info.interlaced {
			im.unusable = true
			return false
		}
		im.pngMeta = &info
	}
	img, fmtName, err := decodeBoundedImage(im.origRaw, im.origMIME, decodeUsed)
	if err != nil {
		im.unusable = true
		return false
	}
	im.decImg = img
	im.decFmt = fmtName
	return true
}

func (im *budgetImage) isOpaque() bool {
	if im.opaque != nil {
		return *im.opaque
	}
	if im.decImg == nil {
		return false
	}
	v := isOpaqueImage(im.decImg)
	im.opaque = &v
	return v
}

func jsonStringLiteral(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(buf.String(), "\n")
}

func parseSupportedDataURL(u string) (mime string, b64 string, ok bool) {
	if len(u) < len("data:image/png;base64,") {
		return "", "", false
	}
	if !strings.EqualFold(u[:5], "data:") {
		return "", "", false
	}
	rest := u[5:]
	comma := strings.IndexByte(rest, ',')
	if comma <= 0 {
		return "", "", false
	}
	meta := rest[:comma]
	b64 = rest[comma+1:]
	if !strings.HasSuffix(strings.ToLower(meta), ";base64") {
		return "", "", false
	}
	m := meta[:len(meta)-len(";base64")]
	if semi := strings.IndexByte(m, ';'); semi >= 0 {
		m = m[:semi]
	}
	norm, ok := normalizeBudgetMIME(m)
	if !ok {
		return "", "", false
	}
	return norm, b64, true
}

func normalizeBudgetMIME(m string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "image/png":
		return "image/png", true
	case "image/jpeg", "image/jpg":
		return "image/jpeg", true
	case "image/webp":
		return "image/webp", true
	default:
		return "", false
	}
}

func validSpan(body []byte, r gjson.Result) bool {
	return r.Exists() && r.Index > 0 && r.Index+len(r.Raw) <= len(body) && string(body[r.Index:r.Index+len(r.Raw)]) == r.Raw
}

func collectBudgetImages(to provider.Protocol, body []byte) []budgetImage {
	var items []gjson.Result
	getIn(body, historyOf(to)).ForEach(func(_, it gjson.Result) bool {
		items = append(items, it)
		return true
	})
	keep := latestUser(to, items)
	var out []budgetImage

	var walk func(msgIdx int, isProt bool, v gjson.Result, depth int)
	walk = func(msgIdx int, isProt bool, v gjson.Result, depth int) {
		if depth > 6 || (!v.IsObject() && !v.IsArray()) {
			return
		}
		if v.IsObject() {
			if dropText := imageWithText(to, v, imageLeftOut); dropText != "" && validSpan(body, v) {
				im := budgetImage{
					msgIdx:      msgIdx,
					isProtected: isProt,
					kind:        imgKindDropOnly,
					partAt:      v.Index,
					partEnd:     v.Index + len(v.Raw),
					dropText:    dropText,
				}
				switch to {
				case provider.Chat, provider.Responses:
					var urlField gjson.Result
					if to == provider.Chat && v.Get("type").String() == "image_url" {
						urlField = v.Get("image_url.url")
					} else if v.Get("type").String() == "input_image" {
						urlField = v.Get("image_url")
					}
					if validSpan(body, urlField) {
						if mime, b64, ok := parseSupportedDataURL(urlField.String()); ok {
							im.kind = imgKindDataURL
							im.urlAt = urlField.Index
							im.urlEnd = urlField.Index + len(urlField.Raw)
							im.origMIME = mime
							im.origB64 = b64
							im.hash = sha256.Sum256([]byte(urlField.String()))
						}
					}
				case provider.Anthropic:
					if v.Get("source.type").String() == "base64" {
						mf := v.Get("source.media_type")
						df := v.Get("source.data")
						if validSpan(body, mf) && validSpan(body, df) && (mf.Index+len(mf.Raw) <= df.Index || df.Index+len(df.Raw) <= mf.Index) {
							if mime, ok := normalizeBudgetMIME(mf.String()); ok {
								im.kind = imgKindSplitFields
								im.mimeAt, im.mimeEnd = mf.Index, mf.Index+len(mf.Raw)
								im.dataAt, im.dataEnd = df.Index, df.Index+len(df.Raw)
								im.origMIME = mime
								im.origB64 = df.String()
								im.hash = sha256.Sum256([]byte(mime + "," + im.origB64))
							}
						}
					}
				case provider.Gemini:
					for _, k := range []string{"inlineData", "inline_data"} {
						d := v.Get(k)
						if !d.IsObject() {
							continue
						}
						mf := d.Get("mimeType")
						if !mf.Exists() {
							mf = d.Get("mime_type")
						}
						df := d.Get("data")
						if validSpan(body, mf) && validSpan(body, df) && (mf.Index+len(mf.Raw) <= df.Index || df.Index+len(df.Raw) <= mf.Index) {
							if mime, ok := normalizeBudgetMIME(mf.String()); ok {
								im.kind = imgKindSplitFields
								im.mimeAt, im.mimeEnd = mf.Index, mf.Index+len(mf.Raw)
								im.dataAt, im.dataEnd = df.Index, df.Index+len(df.Raw)
								im.origMIME = mime
								im.origB64 = df.String()
								im.hash = sha256.Sum256([]byte(mime + "," + im.origB64))
							}
						}
						break
					}
				}
				if im.kind != imgKindDropOnly || len(v.Raw) >= 1<<10 {
					if im.kind == imgKindDropOnly && im.hash == ([sha256.Size]byte{}) {
						im.hash = sha256.Sum256([]byte(v.Raw))
					}
					out = append(out, im)
				}
				return
			}
		}
		v.ForEach(func(_, c gjson.Result) bool {
			walk(msgIdx, isProt, c, depth+1)
			return true
		})
	}
	for i, it := range items {
		isProt := keep >= 0 && i >= keep
		walk(i, isProt, it, 0)
	}
	return out
}

type imgSnapKind int

const (
	snapOrig imgSnapKind = iota
	snapCompressed
	snapDropped
)

type imgSnapshot struct {
	kind  imgSnapKind
	tier  int
	raw   []byte
	mime  string
	delta int // exact wire byte delta relative to original body
	edits []byteEdit
}

func makeCompressedSnapshot(im *budgetImage, tier int, raw []byte, mime string) imgSnapshot {
	b64 := base64.StdEncoding.EncodeToString(raw)
	switch im.kind {
	case imgKindDataURL:
		lit := jsonStringLiteral("data:" + mime + ";base64," + b64)
		return imgSnapshot{
			kind:  snapCompressed,
			tier:  tier,
			raw:   raw,
			mime:  mime,
			delta: len(lit) - (im.urlEnd - im.urlAt),
			edits: []byteEdit{{at: im.urlAt, end: im.urlEnd, text: lit}},
		}
	case imgKindSplitFields:
		mLit := jsonStringLiteral(mime)
		dLit := jsonStringLiteral(b64)
		return imgSnapshot{
			kind:  snapCompressed,
			tier:  tier,
			raw:   raw,
			mime:  mime,
			delta: (len(mLit) - (im.mimeEnd - im.mimeAt)) + (len(dLit) - (im.dataEnd - im.dataAt)),
			edits: []byteEdit{
				{at: im.mimeAt, end: im.mimeEnd, text: mLit},
				{at: im.dataAt, end: im.dataEnd, text: dLit},
			},
		}
	}
	return imgSnapshot{}
}

func makeDroppedSnapshot(im *budgetImage) imgSnapshot {
	return imgSnapshot{
		kind:  snapDropped,
		tier:  5,
		delta: len(im.dropText) - (im.partEnd - im.partAt),
		edits: []byteEdit{{at: im.partAt, end: im.partEnd, text: im.dropText}},
	}
}

func encodeTierCandidate(im *budgetImage, tier int, decodeUsed *int64) ([]byte, string, bool) {
	if im.kind == imgKindDropOnly || im.unusable {
		return nil, "", false
	}
	if !im.ensureOrig() {
		return nil, "", false
	}
	spec := ""
	switch tier {
	case 1:
		if im.origMIME != "image/png" {
			return nil, "", false
		}
		spec = "t1"
	case 2:
		spec = "t2-q85"
	case 3:
		spec = "t3-s85"
	case 4:
		spec = "t4-s70-q75"
	default:
		return nil, "", false
	}
	if raw, mime, ok := budgetCacheGet(im.hash, spec); ok {
		return raw, mime, true
	}

	var outRaw []byte
	var outMIME string

	switch tier {
	case 1:
		info, err := parsePNGChunks(im.origRaw)
		if err != nil || info.animated || info.interlaced {
			im.unusable = true
			return nil, "", false
		}
		if _, err := checkDecodeBudget(info.width, info.height, nil); err != nil {
			im.unusable = true
			return nil, "", false
		}
		im.pngMeta = &info
		best := buildChunkStrippedPNG(info)
		if !im.ensureDecoded(decodeUsed) {
			if len(best) > 0 && len(best) < len(im.origRaw) {
				budgetCachePut(im.hash, spec, best, "image/png")
				return best, "image/png", true
			}
			return nil, "", false
		}
		safe := collectSafePNGChunks(info, false)
		if reenc, err := encodeBestPNG(im.decImg, safe); err == nil && len(reenc) < len(best) {
			best = reenc
		}
		if len(best) > 0 && len(best) < len(im.origRaw) {
			outRaw, outMIME = best, "image/png"
		}

	case 2:
		if !im.ensureDecoded(decodeUsed) {
			return nil, "", false
		}
		if im.origMIME == "image/png" && im.pngMeta != nil && im.pngMeta.hdr {
			return nil, "", false
		}
		if im.origMIME == "image/png" && !im.isOpaque() {
			return nil, "", false
		}
		if enc, err := encodeJPEGQuality(im.decImg, 85); err == nil && len(enc) < len(im.origRaw) {
			outRaw, outMIME = enc, "image/jpeg"
		}

	case 3, 4:
		if !im.ensureDecoded(decodeUsed) {
			return nil, "", false
		}
		b := im.decImg.Bounds()
		w, h := b.Dx(), b.Dy()
		scale := 0.85
		jpegQ := 85
		if tier == 4 {
			scale = 0.70
			jpegQ = 75
		}
		newW, newH, resized := computeBudgetResizeDims(w, h, scale)
		targetImg := im.decImg
		if resized {
			targetImg = triangleResize(im.decImg, newW, newH)
		}
		isHDR := im.origMIME == "image/png" && im.pngMeta != nil && im.pngMeta.hdr
		keepPNG := im.origMIME == "image/png" && (isHDR || !im.isOpaque())
		if keepPNG {
			if !resized {
				return nil, "", false
			}
			var safe []pngChunk
			if im.pngMeta != nil {
				safe = collectSafePNGChunks(*im.pngMeta, true)
			}
			if enc, err := encodeBestPNG(targetImg, safe); err == nil && len(enc) < len(im.origRaw) {
				outRaw, outMIME = enc, "image/png"
			}
		} else {
			if !resized && tier == 3 {
				return nil, "", false
			}
			if enc, err := encodeJPEGQuality(targetImg, jpegQ); err == nil && len(enc) < len(im.origRaw) {
				outRaw, outMIME = enc, "image/jpeg"
			}
		}
	}

	if len(outRaw) == 0 || outMIME == "" {
		return nil, "", false
	}
	budgetCachePut(im.hash, spec, outRaw, outMIME)
	return outRaw, outMIME, true
}

type applyStep struct {
	imgIdx  int
	prevVer int
	newVer  int
}

func applyByteEdits(body []byte, edits []byteEdit) []byte {
	if len(edits) == 0 {
		return body
	}
	// Insertion-sort edits by start offset (tiny slice, avoids extra slices.SortFunc imports if desired, or sort cleanly).
	for i := 1; i < len(edits); i++ {
		cur := edits[i]
		j := i - 1
		for j >= 0 && edits[j].at > cur.at {
			edits[j+1] = edits[j]
			j--
		}
		edits[j+1] = cur
	}
	var outLen = len(body)
	prevEnd := 0
	for _, e := range edits {
		if e.at < prevEnd || e.end < e.at || e.end > len(body) {
			return body
		}
		outLen += len(e.text) - (e.end - e.at)
		prevEnd = e.end
	}
	var b bytes.Buffer
	b.Grow(outLen)
	last := 0
	for _, e := range edits {
		b.Write(body[last:e.at])
		b.WriteString(e.text)
		last = e.end
	}
	b.Write(body[last:])
	return b.Bytes()
}

// fitImageBudget fits body under hardCap (and every inline image under perImageMax)
// using the 5-tier ladder while protecting the current turn's images (latestUser+)
// and rolling back unnecessary degradation steps once under budget.
func fitImageBudget(to provider.Protocol, body []byte, hardCap, perImageMax int) (out []byte, dropped int, ok bool) {
	out, dropped, _, ok = fitImageBudgetWithOptions(to, body, budgetFitOptions{
		hardCap:     hardCap,
		triggerCap:  hardCap,
		softTarget:  hardCap,
		protTarget:  hardCap,
		dropTrigger: hardCap,
		perImageMax: perImageMax,
	})
	return out, dropped, ok
}

// fitImageBudgetWithOptions fits body using separate trigger, soft-target (hysteresis),
// protected-image, and drop thresholds, applying sticky historical tiers first and
// compressing newer history images before older ones to maximize upstream KV prefix cache hits.
func fitImageBudgetWithOptions(to provider.Protocol, body []byte, opts budgetFitOptions) (out []byte, dropped int, updates []stickyTierUpdate, ok bool) {
	if opts.stickyTier == nil &&
		(opts.triggerCap <= 0 || len(body) <= opts.triggerCap) &&
		(opts.perImageMax <= 0 || len(body) <= opts.perImageMax) {
		if opts.hardCap > 0 && len(body) > opts.hardCap {
			return body, 0, nil, false
		}
		return body, 0, nil, true
	}

	imgs := collectBudgetImages(to, body)
	if len(imgs) == 0 {
		return body, 0, nil, opts.hardCap <= 0 || len(body) <= opts.hardCap
	}

	versions := make([][]imgSnapshot, len(imgs))
	curVer := make([]int, len(imgs))
	floorVer := make([]int, len(imgs))
	for i := range imgs {
		versions[i] = []imgSnapshot{{kind: snapOrig}}
	}

	totalLen := len(body)
	var steps []applyStep
	var decodeUsed int64
	deadline := time.Now().Add(budgetDeadline)

	applySnap := func(idx int, snap imgSnapshot) {
		prevVer := curVer[idx]
		versions[idx] = append(versions[idx], snap)
		newVer := len(versions[idx]) - 1
		curVer[idx] = newVer
		totalLen += snap.delta - versions[idx][prevVer].delta
		steps = append(steps, applyStep{imgIdx: idx, prevVer: prevVer, newVer: newVer})
	}

	canDrop := func(idx int) bool {
		if imgs[idx].isProtected {
			return false
		}
		if imgs[idx].partEnd-imgs[idx].partAt < 1<<10 || imgs[idx].dropText == "" {
			return false
		}
		return validSpan(body, gjson.Result{Index: imgs[idx].partAt, Raw: string(body[imgs[idx].partAt:imgs[idx].partEnd])})
	}

	// Step 0: apply previously committed sticky tiers before checking triggers so
	// established history prefixes stay byte-identical once back under triggerCap.
	if opts.stickyTier != nil {
		for i := range imgs {
			if imgs[i].hash == ([sha256.Size]byte{}) {
				continue
			}
			stier := opts.stickyTier(imgs[i].msgIdx, imgs[i].hash)
			if stier <= 0 {
				continue
			}
			if stier >= 5 {
				if canDrop(i) {
					snap := makeDroppedSnapshot(&imgs[i])
					if snap.delta < 0 {
						versions[i] = append(versions[i], snap)
						curVer[i] = 1
						floorVer[i] = 1
						totalLen += snap.delta
					}
				}
				continue
			}
			if raw, mime, encOK := encodeTierCandidate(&imgs[i], stier, &decodeUsed); encOK {
				snap := makeCompressedSnapshot(&imgs[i], stier, raw, mime)
				if snap.delta < 0 {
					versions[i] = append(versions[i], snap)
					curVer[i] = 1
					floorVer[i] = 1
					totalLen += snap.delta
				}
			}
		}
	}

	curRawLen := func(idx int) int {
		s := versions[idx][curVer[idx]]
		if s.kind == snapCompressed {
			return len(s.raw)
		}
		if s.kind == snapDropped {
			return 0
		}
		if imgs[idx].ensureOrig() {
			return len(imgs[idx].origRaw)
		}
		return 0
	}

	overPerImg := func(idx int) bool {
		if opts.perImageMax <= 0 {
			return false
		}
		cur := versions[idx][curVer[idx]]
		if cur.kind == snapCompressed {
			return len(cur.raw) > opts.perImageMax
		}
		if cur.kind == snapDropped {
			return false
		}
		if imgs[idx].approxRawBytes() <= opts.perImageMax*9/10 {
			return false
		}
		return imgs[idx].ensureOrig() && len(imgs[idx].origRaw) > opts.perImageMax
	}

	needPerImg := false
	if opts.perImageMax > 0 {
		for i := range imgs {
			if overPerImg(i) {
				needPerImg = true
				break
			}
		}
	}

	needTrigger := opts.triggerCap > 0 && totalLen > opts.triggerCap
	if !needTrigger && !needPerImg {
		var edits []byteEdit
		for i := range imgs {
			snap := versions[i][curVer[i]]
			if snap.kind == snapOrig {
				continue
			}
			if snap.kind == snapDropped {
				dropped++
			}
			edits = append(edits, snap.edits...)
			if snap.tier > 0 && imgs[i].hash != ([sha256.Size]byte{}) {
				updates = append(updates, stickyTierUpdate{msgIdx: imgs[i].msgIdx, hash: imgs[i].hash, tier: snap.tier})
			}
		}
		if len(edits) == 0 {
			return body, 0, nil, opts.hardCap <= 0 || len(body) <= opts.hardCap
		}
		out = applyByteEdits(body, edits)
		if opts.hardCap > 0 && len(out) > opts.hardCap {
			return body, 0, nil, false
		}
		return out, dropped, updates, true
	}

	// Phase A: enforce perImageMax for every oversized image.
	if needPerImg {
		for i := range imgs {
			if time.Now().After(deadline) {
				break
			}
			if !overPerImg(i) || imgs[i].kind == imgKindDropOnly {
				continue
			}
			for tier := 1; tier <= 4; tier++ {
				if time.Now().After(deadline) {
					break
				}
				if tier <= versions[i][curVer[i]].tier {
					continue
				}
				raw, mime, encOK := encodeTierCandidate(&imgs[i], tier, &decodeUsed)
				if !encOK {
					continue
				}
				snap := makeCompressedSnapshot(&imgs[i], tier, raw, mime)
				if len(raw) < curRawLen(i) || snap.delta < versions[i][curVer[i]].delta {
					applySnap(i, snap)
				}
				if curRawLen(i) <= opts.perImageMax {
					break
				}
			}
		}
	}

	tryCompress := func(idx, tier int) {
		if imgs[idx].kind == imgKindDropOnly {
			return
		}
		cur := versions[idx][curVer[idx]]
		if cur.kind == snapDropped || cur.tier >= tier {
			return
		}
		raw, mime, encOK := encodeTierCandidate(&imgs[idx], tier, &decodeUsed)
		if !encOK {
			return
		}
		snap := makeCompressedSnapshot(&imgs[idx], tier, raw, mime)
		if snap.delta < cur.delta {
			applySnap(idx, snap)
		}
	}

	totalTarget := opts.softTarget
	if totalTarget <= 0 {
		totalTarget = opts.hardCap
	}
	protCap := opts.protTarget
	if protCap <= 0 {
		protCap = opts.hardCap
	}
	dropTrig := opts.dropTrigger
	if dropTrig <= 0 {
		dropTrig = opts.hardCap
	}

	compressHistory := (needTrigger || (opts.triggerCap > 0 && totalLen > opts.triggerCap)) && totalTarget > 0 && totalLen > totalTarget

	// Pass 0: Tier 1 lossless PNG metadata optimization on protected current-turn images (0 KV prefix cost).
	if compressHistory {
		for i := 0; i < len(imgs) && totalLen > totalTarget; i++ {
			if time.Now().After(deadline) {
				break
			}
			if imgs[i].isProtected {
				tryCompress(i, 1)
			}
		}
	}

	// Pass 1: prefix-preserving full-res compression on history images (newest -> oldest, Tier 1 then Tier 2).
	if compressHistory && totalLen > totalTarget {
		for i := len(imgs) - 1; i >= 0 && totalLen > totalTarget; i-- {
			if time.Now().After(deadline) {
				break
			}
			if imgs[i].isProtected {
				continue
			}
			tryCompress(i, 1)
			if totalLen <= totalTarget {
				break
			}
			tryCompress(i, 2)
		}
	}

	// Pass 2: prefix-preserving resize on history images (newest -> oldest, Tier 3 then Tier 4).
	if compressHistory && totalLen > totalTarget {
		for i := len(imgs) - 1; i >= 0 && totalLen > totalTarget; i-- {
			if time.Now().After(deadline) {
				break
			}
			if imgs[i].isProtected {
				continue
			}
			tryCompress(i, 3)
			if totalLen <= totalTarget {
				break
			}
			tryCompress(i, 4)
		}
	}

	// Pass 3: protected lossy fallback (Tiers 2..4) only if still over protCap.
	if (compressHistory || (opts.hardCap > 0 && totalLen > opts.hardCap)) && protCap > 0 && totalLen > protCap {
		for tier := 2; tier <= 4 && totalLen > protCap; tier++ {
			for i := 0; i < len(imgs) && totalLen > protCap; i++ {
				if time.Now().After(deadline) {
					break
				}
				if imgs[i].isProtected {
					tryCompress(i, tier)
				}
			}
		}
	}

	// Pass 4: Tier 5 drops oldest history images down to totalTarget (never protected) if still over dropTrig.
	if (needTrigger || (opts.hardCap > 0 && totalLen > opts.hardCap)) && dropTrig > 0 && totalLen > dropTrig {
		dropGoal := totalTarget
		if dropGoal <= 0 {
			dropGoal = dropTrig
		}
		for i := 0; i < len(imgs) && totalLen > dropGoal; i++ {
			if !canDrop(i) {
				continue
			}
			cur := versions[i][curVer[i]]
			if cur.kind == snapDropped {
				continue
			}
			snap := makeDroppedSnapshot(&imgs[i])
			if snap.delta < cur.delta {
				applySnap(i, snap)
			}
		}
	}

	if opts.hardCap > 0 && totalLen > opts.hardCap {
		return body, 0, nil, false
	}

	// Phase C: stepwise rollback of unnecessary steps in reverse application order,
	// capped by rollbackCap (softTarget) and never rolling back below sticky floorVer[i].
	rawLenForSnap := func(idx int, snap imgSnapshot) int {
		if snap.kind == snapCompressed {
			return len(snap.raw)
		}
		if snap.kind == snapDropped {
			return 0
		}
		if imgs[idx].origLoaded {
			return len(imgs[idx].origRaw)
		}
		return imgs[idx].approxRawBytes()
	}
	rollbackCap := opts.softTarget
	if rollbackCap <= 0 {
		rollbackCap = opts.hardCap
	}
	for h := len(steps) - 1; h >= 0; h-- {
		st := steps[h]
		if curVer[st.imgIdx] != st.newVer || st.prevVer < floorVer[st.imgIdx] {
			continue
		}
		prev := versions[st.imgIdx][st.prevVer]
		cur := versions[st.imgIdx][st.newVer]
		if opts.perImageMax > 0 && rawLenForSnap(st.imgIdx, prev) > opts.perImageMax {
			continue
		}
		newTotal := totalLen + prev.delta - cur.delta
		if rollbackCap > 0 && newTotal > rollbackCap {
			continue
		}
		curVer[st.imgIdx] = st.prevVer
		totalLen = newTotal
	}

	var edits []byteEdit
	for i := range imgs {
		snap := versions[i][curVer[i]]
		if snap.kind == snapOrig {
			continue
		}
		if snap.kind == snapDropped {
			dropped++
		}
		edits = append(edits, snap.edits...)
		if snap.tier > 0 && imgs[i].hash != ([sha256.Size]byte{}) {
			updates = append(updates, stickyTierUpdate{msgIdx: imgs[i].msgIdx, hash: imgs[i].hash, tier: snap.tier})
		}
	}
	if len(edits) == 0 {
		if opts.hardCap > 0 && len(body) > opts.hardCap {
			return body, 0, nil, false
		}
		return body, 0, nil, true
	}
	out = applyByteEdits(body, edits)
	if opts.hardCap > 0 && len(out) > opts.hardCap {
		return body, 0, nil, false
	}
	return out, dropped, updates, true
}
