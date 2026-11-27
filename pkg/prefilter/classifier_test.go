package prefilter

import (
	"bytes"
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy(nil); got != 0 {
		t.Fatalf("empty entropy = %v", got)
	}
	if got := ShannonEntropy(bytes.Repeat([]byte{'A'}, 1024)); got != 0 {
		t.Fatalf("constant entropy = %v", got)
	}
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	if got := ShannonEntropy(data); math.Abs(got-8) > 1e-9 {
		t.Fatalf("uniform entropy = %v, want 8", got)
	}
}

func TestGateMatchesHeaderSizeAndEntropy(t *testing.T) {
	gate := emptyGate()
	gate.Magics = []MagicRequirement{
		{Name: "mz", Bytes: []byte("MZ")},
	}
	gate.MinSize = 10
	gate.MaxSize = 20
	gate.MinEntropy = 4
	gate.MaxEntropy = 6

	features := FileFeatures{
		Size:         15,
		Header:       []byte("MZ hello"),
		HeaderKnown:  true,
		Entropy:      5,
		EntropyKnown: true,
	}
	if !gate.Matches(features) {
		t.Fatal("gate should match")
	}

	features.Header = []byte("ELF hello")
	if gate.Matches(features) {
		t.Fatal("gate should not match wrong header")
	}

	features.Header = []byte("MZ hello")
	features.Entropy = 7
	if gate.Matches(features) {
		t.Fatal("gate should not match entropy above max")
	}

	features.EntropyKnown = false
	if !gate.Matches(features) {
		t.Fatal("unknown entropy must fail open")
	}
}

func TestMagicCaseAndWide(t *testing.T) {
	if !(MagicRequirement{Bytes: []byte("mz"), CaseInsensitive: true}).Matches([]byte("MZ...."), true) {
		t.Fatal("case-insensitive magic did not match")
	}
	if !(MagicRequirement{Bytes: []byte("MZ"), Wide: true}).Matches([]byte("M\x00Z\x00"), true) {
		t.Fatal("wide magic did not match")
	}
	if (MagicRequirement{Bytes: []byte("MZ")}).Matches([]byte("M"), true) {
		t.Fatal("short header must not match")
	}
}

func TestExtractFeaturesFromReaderAt(t *testing.T) {
	data := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{'x'}, 1000)...)
	c := NewClassifier([]ShardProfile{{
		Gates: []Gate{func() Gate {
			g := emptyGate()
			g.MinEntropy = 1
			return g
		}()},
	}})
	features := c.ExtractFeatures("x", bytes.NewReader(data), int64(len(data)))
	if !features.HeaderKnown || features.Header[0] != 0x7f {
		t.Fatalf("header not extracted: %#v", features)
	}
	if !features.EntropyKnown {
		t.Fatal("entropy was requested but not computed")
	}
}
