package scan

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/yararules"
)

func TestShardEngineMatchesLegacyFullScan(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	filesDir := filepath.Join(dir, "files")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rulesSource := `
import "math"

private rule is_elf {
  strings:
    $h = { 7F 45 4C 46 }
  condition:
    $h at 0
}

rule ELF_Needle : malware test {
  strings:
    $h = { 7F 45 4C 46 }
    $n = "needle"
  condition:
    $h at 0 and is_elf and $n
}

rule PE_MZ {
  strings:
    $mz = { 4D 5A }
  condition:
    $mz at 0
}

rule Text_Needle {
  strings:
    $n = "needle"
  condition:
    $n
}

rule Small_File {
  condition:
    filesize < 64
}

rule High_Entropy {
  condition:
    math.entropy(0, filesize) > 7.5
}
`
	if err := os.WriteFile(filepath.Join(rulesDir, "test.yar"), []byte(rulesSource), 0o644); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(7))
	high := make([]byte, 8192)
	if _, err := rng.Read(high); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"elf.bin":   append([]byte{0x7f, 'E', 'L', 'F'}, append([]byte("needle"), make([]byte, 256)...)...),
		"pe.bin":    append([]byte{'M', 'Z'}, []byte("needle")...),
		"text.txt":  []byte("hello needle world\n"),
		"high.bin":  high,
		"small.txt": []byte("x"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(filesDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	yaraRules := yararules.New(rulesDir)
	if err := yaraRules.Compile(constants.Filescan, false); err != nil {
		t.Fatal(err)
	}
	legacyScanner, err := yaraRules.NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	legacy := NewLegacyEngine(legacyScanner)

	shards, err := yaraRules.CompileShards(4, false)
	if err != nil {
		t.Fatal(err)
	}
	sharded := NewShardEngine(shards, EngineOptions{
		Workers:       4,
		Prefilter:     true,
		EnableEntropy: true,
	})

	for name := range files {
		path := filepath.Join(filesDir, name)
		legacyMatches := scanSet(t, legacy, path)
		shardMatches := scanSet(t, sharded, path)
		if !equalStrings(legacyMatches, shardMatches) {
			t.Fatalf("%s: legacy matches %v, shard matches %v", name, legacyMatches, shardMatches)
		}
	}
	if stats := sharded.Stats(); stats.ShardSkips <= 0 || stats.EntropyChecks <= 0 {
		t.Fatalf("expected prefilter activity, got %+v", stats)
	}

	shadow := NewShardEngine(shards, EngineOptions{
		Workers:       4,
		Prefilter:     true,
		Shadow:        true,
		EnableEntropy: true,
	})
	for name := range files {
		scanSet(t, shadow, filepath.Join(filesDir, name))
	}
	if misses := shadow.Stats().ShadowMisses; misses != 0 {
		t.Fatalf("shadow prefilter would have skipped %d matching shards", misses)
	}
}

func scanSet(t *testing.T, engine *Engine, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found, err := engine.ScanReader(path, path, bytes.NewReader(data), int64(len(data)), "")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(found))
	for _, ioc := range found {
		out = append(out, ioc.RuleName+"|"+ioc.CompleteFilename)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
