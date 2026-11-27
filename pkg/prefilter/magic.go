package prefilter

import "bytes"

// HeaderSize is the number of leading bytes inspected by the header filter.
const HeaderSize = 4096

// MagicRequirement describes bytes that must be present at a fixed offset for
// a rule (or shard) to have a chance of matching.
type MagicRequirement struct {
	Name            string
	Offset          int
	Bytes           []byte
	CaseInsensitive bool
	Wide            bool
}

// Matches reports whether header satisfies the requirement. A false result is
// only returned when the header was read successfully and definitely does not
// contain the required bytes.
func (m MagicRequirement) Matches(header []byte, headerKnown bool) bool {
	if !headerKnown {
		return true
	}
	if m.Offset < 0 {
		return true
	}

	length := m.PatternLen()
	if m.Offset+length > HeaderSize {
		// The requirement reaches beyond the header sample; fail open.
		return true
	}
	pattern := m.Bytes
	if m.Wide {
		pattern = make([]byte, 0, len(m.Bytes)*2)
		for _, b := range m.Bytes {
			pattern = append(pattern, b, 0)
		}
	}
	if len(pattern) == 0 {
		return true
	}

	end := m.Offset + len(pattern)
	if end > len(header) {
		return false
	}
	got := header[m.Offset:end]
	if m.CaseInsensitive && !m.Wide {
		return bytes.EqualFold(got, pattern)
	}
	if m.CaseInsensitive {
		for i := range pattern {
			if i%2 == 0 {
				if lower(got[i]) != lower(pattern[i]) {
					return false
				}
			} else if got[i] != pattern[i] {
				return false
			}
		}
		return true
	}
	return bytes.Equal(got, pattern)
}

// PatternLen returns the number of bytes the requirement occupies.
func (m MagicRequirement) PatternLen() int {
	if m.Wide {
		return len(m.Bytes) * 2
	}
	return len(m.Bytes)
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// Known magic signatures are used for diagnostics and for rules that rely on
// YARA modules with an unambiguous file-format prerequisite.
var (
	MagicELF       = MagicRequirement{Name: "elf", Bytes: []byte{0x7f, 'E', 'L', 'F'}}
	MagicPE        = MagicRequirement{Name: "pe", Bytes: []byte{'M', 'Z'}}
	MagicMachO32   = MagicRequirement{Name: "macho32", Bytes: []byte{0xfe, 0xed, 0xfa, 0xce}}
	MagicMachO64   = MagicRequirement{Name: "macho64", Bytes: []byte{0xfe, 0xed, 0xfa, 0xcf}}
	MagicMachO32LE = MagicRequirement{Name: "macho32le", Bytes: []byte{0xce, 0xfa, 0xed, 0xfe}}
	MagicMachO64LE = MagicRequirement{Name: "macho64le", Bytes: []byte{0xcf, 0xfa, 0xed, 0xfe}}
	MagicPDF       = MagicRequirement{Name: "pdf", Bytes: []byte("%PDF-")}
	MagicZIP       = MagicRequirement{Name: "zip", Bytes: []byte{'P', 'K', 0x03, 0x04}}
	MagicGZIP      = MagicRequirement{Name: "gzip", Bytes: []byte{0x1f, 0x8b}}
	MagicBzip2     = MagicRequirement{Name: "bzip2", Bytes: []byte{'B', 'Z', 'h'}}
	MagicXZ        = MagicRequirement{Name: "xz", Bytes: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}}
	Magic7Z        = MagicRequirement{Name: "7z", Bytes: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}}
	MagicRAR       = MagicRequirement{Name: "rar", Bytes: []byte{'R', 'a', 'r', '!'}}
	MagicSQLite    = MagicRequirement{Name: "sqlite", Bytes: []byte("SQLite format 3\x00")}
	MagicJavaClass = MagicRequirement{Name: "java-class", Bytes: []byte{0xca, 0xfe, 0xba, 0xbe}}
	MagicWASM      = MagicRequirement{Name: "wasm", Bytes: []byte{0x00, 'a', 's', 'm'}}
)

// KnownMagicSignatures returns all built-in signatures. It is exported for
// diagnostics and tests.
func KnownMagicSignatures() []MagicRequirement {
	return []MagicRequirement{
		MagicELF, MagicPE, MagicMachO32, MagicMachO64, MagicMachO32LE, MagicMachO64LE,
		MagicPDF, MagicZIP, MagicGZIP, MagicBzip2, MagicXZ, Magic7Z, MagicRAR,
		MagicSQLite, MagicJavaClass, MagicWASM,
	}
}

// MatchMagic returns the names of known signatures present at the file header.
func MatchMagic(header []byte, known bool) []string {
	if !known {
		return nil
	}
	out := make([]string, 0, 2)
	for _, sig := range KnownMagicSignatures() {
		if sig.Matches(header, true) {
			out = append(out, sig.Name)
		}
	}
	return out
}
