package gateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"math"
	"strings"

	_ "golang.org/x/image/webp"
)

const (
	forkMaxDecodePixels   int64 = 9_000_000
	forkMaxDecodeBytes    int64 = 36 << 20
	forkTotalDecodeBudget int64 = 96 << 20
	forkMinShortSide            = 720
	forkMaxAspectRatio          = 3
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

var errImageDecodeLimit = errors.New("image exceeds decode safety limit")

type pngChunk struct {
	typ  string
	data []byte
	raw  []byte // full chunk bytes: length + type + data + crc
}

type pngInfo struct {
	width      int
	height     int
	interlaced bool
	animated   bool
	hdr        bool
	chunks     []pngChunk
}

func isSafeColorOrGeomChunk(typ string) bool {
	switch typ {
	case "sRGB", "pHYs", "gAMA", "cHRM", "cICP", "mDCv", "cLLi", "iCCP":
		return true
	}
	return false
}

func isResizedSafeColorChunk(typ string) bool {
	switch typ {
	case "sRGB", "gAMA", "cHRM", "cICP", "mDCv", "cLLi", "iCCP":
		return true
	}
	return false
}

func parsePNGChunks(raw []byte) (pngInfo, error) {
	var info pngInfo
	if len(raw) < len(pngSignature)+12 || !bytes.Equal(raw[:8], pngSignature) {
		return info, errors.New("not a PNG")
	}
	off := 8
	sawIHDR := false
	sawIEND := false
	for off < len(raw) {
		if off+12 > len(raw) {
			return info, errors.New("truncated PNG chunk header")
		}
		clen := int(binary.BigEndian.Uint32(raw[off : off+4]))
		if clen < 0 || off+12+clen > len(raw) {
			return info, errors.New("truncated PNG chunk body")
		}
		typBytes := raw[off+4 : off+8]
		typ := string(typBytes)
		data := raw[off+8 : off+8+clen]
		wantCRC := binary.BigEndian.Uint32(raw[off+8+clen : off+12+clen])
		gotCRC := crc32.ChecksumIEEE(raw[off+4 : off+8+clen])
		if gotCRC != wantCRC {
			return info, errors.New("PNG CRC32 mismatch")
		}
		chunkRaw := raw[off : off+12+clen]
		if !sawIHDR {
			if typ != "IHDR" || clen != 13 {
				return info, errors.New("missing IHDR chunk")
			}
			sawIHDR = true
			info.width = int(binary.BigEndian.Uint32(data[0:4]))
			info.height = int(binary.BigEndian.Uint32(data[4:8]))
			info.interlaced = data[12] != 0
		}
		switch typ {
		case "acTL", "fcTL", "fdAT":
			info.animated = true
		case "cICP", "mDCv", "cLLi":
			info.hdr = true
		}
		info.chunks = append(info.chunks, pngChunk{
			typ:  typ,
			data: data,
			raw:  chunkRaw,
		})
		off += 12 + clen
		if typ == "IEND" {
			sawIEND = true
			break
		}
	}
	if !sawIHDR || !sawIEND || off != len(raw) {
		return info, errors.New("incomplete PNG structure")
	}
	return info, nil
}

// buildChunkStrippedPNG removes iDOT and non-essential metadata (tEXt/iTXt/zTXt/eXIf/tIME/etc.)
// while keeping critical image chunks and safe color/geometry chunks untouched.
func buildChunkStrippedPNG(info pngInfo) []byte {
	var out bytes.Buffer
	out.Grow(len(info.chunks) * 64)
	out.Write(pngSignature)
	for _, ch := range info.chunks {
		if ch.typ == "iDOT" {
			continue
		}
		if ch.typ == "IHDR" || ch.typ == "PLTE" || ch.typ == "IDAT" || ch.typ == "IEND" ||
			ch.typ == "tRNS" || isSafeColorOrGeomChunk(ch.typ) {
			out.Write(ch.raw)
		}
	}
	return out.Bytes()
}

// spliceSafePNGChunks inserts preserved safe chunks directly after IHDR in a
// freshly encoded PNG stream so color/gamma/HDR/DPI metadata is retained.
func spliceSafePNGChunks(encoded []byte, safe []pngChunk) ([]byte, error) {
	if len(safe) == 0 {
		return encoded, nil
	}
	if len(encoded) < 8+12+13 || !bytes.Equal(encoded[:8], pngSignature) {
		return nil, errors.New("invalid encoded PNG")
	}
	ihdrLen := int(binary.BigEndian.Uint32(encoded[8:12]))
	ihdrEnd := 8 + 12 + ihdrLen
	if ihdrLen != 13 || ihdrEnd > len(encoded) || string(encoded[12:16]) != "IHDR" {
		return nil, errors.New("invalid encoded IHDR")
	}
	extraLen := 0
	for _, ch := range safe {
		extraLen += len(ch.raw)
	}
	out := make([]byte, 0, len(encoded)+extraLen)
	out = append(out, encoded[:ihdrEnd]...)
	for _, ch := range safe {
		out = append(out, ch.raw...)
	}
	out = append(out, encoded[ihdrEnd:]...)
	return out, nil
}

func collectSafePNGChunks(info pngInfo, resized bool) []pngChunk {
	var out []pngChunk
	for _, ch := range info.chunks {
		if resized {
			if isResizedSafeColorChunk(ch.typ) {
				out = append(out, ch)
			}
			continue
		}
		if isSafeColorOrGeomChunk(ch.typ) {
			out = append(out, ch)
		}
	}
	return out
}

func checkDecodeBudget(w, h int, decodeUsed *int64) (int64, error) {
	if w <= 0 || h <= 0 {
		return 0, errors.New("invalid image dimensions")
	}
	iw := int64(w)
	ih := int64(h)
	if iw > forkMaxDecodePixels/ih {
		return 0, errImageDecodeLimit
	}
	pixels := iw * ih
	rgbaBytes := pixels * 4
	if pixels > forkMaxDecodePixels || rgbaBytes > forkMaxDecodeBytes {
		return 0, errImageDecodeLimit
	}
	if decodeUsed != nil && *decodeUsed+rgbaBytes > forkTotalDecodeBudget {
		return 0, errImageDecodeLimit
	}
	return rgbaBytes, nil
}

func decodeBoundedImage(raw []byte, mime string, decodeUsed *int64) (image.Image, string, error) {
	if strings.EqualFold(mime, "image/png") {
		info, err := parsePNGChunks(raw)
		if err != nil {
			return nil, "", err
		}
		if info.animated || info.interlaced {
			return nil, "", errors.New("animated or interlaced PNG skipped")
		}
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	rgbaBytes, err := checkDecodeBudget(cfg.Width, cfg.Height, decodeUsed)
	if err != nil {
		return nil, "", err
	}
	if decodeUsed != nil {
		*decodeUsed += rgbaBytes
	}
	img, decFmt, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	if decFmt != "" {
		format = decFmt
	}
	return img, format, nil
}

func isOpaqueImage(img image.Image) bool {
	if op, ok := img.(interface{ Opaque() bool }); ok {
		return op.Opaque()
	}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a != 0xffff {
				return false
			}
		}
	}
	return true
}

func computeBudgetResizeDims(w, h int, scale float64) (int, int, bool) {
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	short := min(w, h)
	long := max(w, h)
	if short <= forkMinShortSide || long > forkMaxAspectRatio*short {
		return 0, 0, false
	}
	newW := max(1, int(math.Round(float64(w)*scale)))
	newH := max(1, int(math.Round(float64(h)*scale)))
	newShort := min(newW, newH)
	if newShort < forkMinShortSide {
		factor := float64(forkMinShortSide) / float64(newShort)
		newW = max(1, int(math.Round(float64(newW)*factor)))
		newH = max(1, int(math.Round(float64(newH)*factor)))
		if newW <= w && newH <= h && min(newW, newH) < forkMinShortSide {
			if w <= h {
				newW = forkMinShortSide
				newH = max(forkMinShortSide, int(math.Round(float64(h)*float64(forkMinShortSide)/float64(w))))
			} else {
				newH = forkMinShortSide
				newW = max(forkMinShortSide, int(math.Round(float64(w)*float64(forkMinShortSide)/float64(h))))
			}
		}
	}
	if newW >= w && newH >= h {
		return 0, 0, false
	}
	return newW, newH, true
}

func encodeBestPNG(img image.Image, safe []pngChunk) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(safe) > 0 {
		spliced, err := spliceSafePNGChunks(out, safe)
		if err != nil {
			return nil, err
		}
		out = spliced
	}
	return out, nil
}

func encodeJPEGQuality(img image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
