package prefilter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuleFilesProfilesSafeConstraints(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "common.yar")
	if err := os.WriteFile(inc, []byte(`
private rule is_elf {
  strings:
    $h = { 7F 45 4C 46 }
  condition:
    $h at 0
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.yar")
	if err := os.WriteFile(main, []byte(`
import "math"
include "common.yar"

rule ELF_With_Tag : malware apt {
  strings:
    $h = { 7F 45 4C 46 }
    $n = "needle" ascii wide
  condition:
    $h at 0 and is_elf and $n
}

rule PE_At_Zero {
  strings:
    $mz = "MZ"
  condition:
    uint16(0) == 0x5a4d and $mz at 0
}

rule Size_Only {
  condition:
    filesize > 100 and filesize <= 200
}

rule Entropy_Only {
  condition:
    math.entropy(0, filesize) > 7.5
}

rule Unknown_Complex {
  strings:
    $a = "abc"
  condition:
    not $a at 0
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	profile, err := ParseRuleFiles([]string{main})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(profile.Rules), 6; got != want {
		t.Fatalf("rules = %d, want %d", got, want)
	}

	byName := make(map[string]RuleProfile)
	for _, rule := range profile.Rules {
		byName[rule.Name] = rule
	}
	elf := byName["ELF_With_Tag"]
	if elf.Always() || len(elf.Gates) == 0 {
		t.Fatalf("ELF rule was not profiled: %#v", elf)
	}
	if !containsDep(elf.Deps, "is_elf") {
		t.Fatalf("dependency missing: %#v", elf.Deps)
	}
	pe := byName["PE_At_Zero"]
	if len(pe.Gates) != 1 || len(pe.Gates[0].Magics) == 0 {
		t.Fatalf("PE rule header gate missing: %#v", pe.Gates)
	}
	sz := byName["Size_Only"]
	if len(sz.Gates) != 1 || sz.Gates[0].MinSize != 101 || sz.Gates[0].MaxSize != 200 {
		t.Fatalf("size gate = %#v", sz.Gates)
	}
	ent := byName["Entropy_Only"]
	if len(ent.Gates) != 1 || ent.Gates[0].MinEntropy <= 7.5 {
		t.Fatalf("entropy gate = %#v", ent.Gates)
	}
	unknown := byName["Unknown_Complex"]
	if !unknown.Always() {
		t.Fatalf("complex rule must have no unsafe gate: %#v", unknown.Gates)
	}
}

func containsDep(deps []string, want string) bool {
	for _, dep := range deps {
		if dep == want {
			return true
		}
	}
	return false
}
