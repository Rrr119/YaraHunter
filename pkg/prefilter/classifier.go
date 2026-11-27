package prefilter

import (
	"io"
)

const (
	unboundedSize    int64   = -1
	unboundedEntropy float64 = -1
	maxEntropy               = 8
)

// Gate is a necessary condition for at least one rule in a shard. All fields
// are conjunctive. A shard with several gates is run when any gate matches.
type Gate struct {
	Magics     []MagicRequirement
	MinSize    int64
	MaxSize    int64
	MinEntropy float64
	MaxEntropy float64
}

func emptyGate() Gate {
	return Gate{
		MinSize:    unboundedSize,
		MaxSize:    unboundedSize,
		MinEntropy: unboundedEntropy,
		MaxEntropy: unboundedEntropy,
	}
}

// Always reports whether the gate carries no useful restriction.
func (g Gate) Always() bool {
	return len(g.Magics) == 0 &&
		g.MinSize == unboundedSize &&
		g.MaxSize == unboundedSize &&
		g.MinEntropy == unboundedEntropy &&
		g.MaxEntropy == unboundedEntropy
}

func (g Gate) merge(other Gate) Gate {
	out := Gate{
		Magics:     append(append([]MagicRequirement{}, g.Magics...), other.Magics...),
		MinSize:    g.MinSize,
		MaxSize:    g.MaxSize,
		MinEntropy: g.MinEntropy,
		MaxEntropy: g.MaxEntropy,
	}
	if out.MinSize == unboundedSize {
		out.MinSize = other.MinSize
	} else if other.MinSize != unboundedSize && other.MinSize > out.MinSize {
		out.MinSize = other.MinSize
	}
	if out.MaxSize == unboundedSize {
		out.MaxSize = other.MaxSize
	} else if other.MaxSize != unboundedSize && other.MaxSize < out.MaxSize {
		out.MaxSize = other.MaxSize
	}
	if out.MinEntropy == unboundedEntropy {
		out.MinEntropy = other.MinEntropy
	} else if other.MinEntropy != unboundedEntropy && other.MinEntropy > out.MinEntropy {
		out.MinEntropy = other.MinEntropy
	}
	if out.MaxEntropy == unboundedEntropy {
		out.MaxEntropy = other.MaxEntropy
	} else if other.MaxEntropy != unboundedEntropy && other.MaxEntropy < out.MaxEntropy {
		out.MaxEntropy = other.MaxEntropy
	}
	return out
}

// FileFeatures contains the information computed once per file and shared by
// all shard decisions.
type FileFeatures struct {
	Size         int64
	Header       []byte
	HeaderKnown  bool
	Entropy      float64
	EntropyKnown bool
}

// Matches reports whether a file can satisfy the gate. It fails open whenever
// a needed feature could not be read.
func (g Gate) Matches(f FileFeatures) bool {
	if g.MinSize != unboundedSize && f.Size < g.MinSize {
		return false
	}
	if g.MaxSize != unboundedSize && f.Size > g.MaxSize {
		return false
	}
	if g.MinEntropy != unboundedEntropy {
		if !f.EntropyKnown {
			return true
		}
		// A tiny margin keeps borderline floating-point values on the
		// "scan it" side.
		if f.Entropy < g.MinEntropy-1e-9 {
			return false
		}
	}
	if g.MaxEntropy != unboundedEntropy {
		if !f.EntropyKnown {
			return true
		}
		if f.Entropy > g.MaxEntropy+1e-9 {
			return false
		}
	}
	for _, magic := range g.Magics {
		if f.Size >= 0 && int64(magic.Offset+magic.PatternLen()) > f.Size {
			return false
		}
		if !magic.Matches(f.Header, f.HeaderKnown) {
			return false
		}
	}
	return true
}

// ShardProfile is the immutable prefilter metadata for one compiled shard.
type ShardProfile struct {
	Name      string
	Always    bool
	Gates     []Gate
	RuleNames []string
}

// NeedEntropy reports whether evaluating this shard needs full-file entropy.
func (p ShardProfile) NeedEntropy() bool {
	if p.Always {
		return false
	}
	for _, gate := range p.Gates {
		if gate.MinEntropy != unboundedEntropy || gate.MaxEntropy != unboundedEntropy {
			return true
		}
	}
	return false
}

// Matches reports whether the shard should be scanned for the file.
func (p ShardProfile) Matches(f FileFeatures) bool {
	if p.Always || len(p.Gates) == 0 {
		return true
	}
	for _, gate := range p.Gates {
		if gate.Matches(f) {
			return true
		}
	}
	return false
}

// RuleSetProfile is the result of statically profiling a YARA rule set.
type RuleSetProfile struct {
	Imports    []string
	Rules      []RuleProfile
	RuleByName map[string]int
}

// RuleProfile is the static description of one top-level YARA rule.
type RuleProfile struct {
	Name    string
	Index   int
	Private bool
	Global  bool
	Source  string
	Deps    []string
	Gates   []Gate

	condition string
}

// Always reports whether the rule has no safe prefilter constraint.
func (r *RuleProfile) Always() bool {
	return len(r.Gates) == 0
}

// Classifier computes file features and makes shard decisions.
type Classifier struct {
	needEntropy bool
}

// NewClassifier creates a classifier for the supplied shard profiles.
func NewClassifier(profiles []ShardProfile) *Classifier {
	c := &Classifier{}
	for _, p := range profiles {
		if p.NeedEntropy() {
			c.needEntropy = true
			break
		}
	}
	return c
}

// NeedEntropy reports whether any shard has an entropy constraint.
func (c *Classifier) NeedEntropy() bool {
	return c.needEntropy
}

// ExtractFeatures reads the file header and, when required, full-file entropy.
func (c *Classifier) ExtractFeatures(path string, r io.ReaderAt, size int64) FileFeatures {
	return c.ExtractFeaturesWithEntropy(path, r, size, true)
}

// ExtractFeaturesWithEntropy is ExtractFeatures with an explicit switch for
// the entropy pass. Disabling entropy makes entropy gates fail open.
func (c *Classifier) ExtractFeaturesWithEntropy(path string, r io.ReaderAt, size int64, withEntropy bool) FileFeatures {
	features := FileFeatures{
		Size:   size,
		Header: make([]byte, 0, HeaderSize),
	}
	if r != nil && size >= 0 {
		header := make([]byte, HeaderSize)
		n := int64(HeaderSize)
		if size < n {
			n = size
		}
		got, err := r.ReadAt(header[:n], 0)
		if err == nil || err == io.EOF {
			features.Header = header[:got]
			features.HeaderKnown = true
		}
	}
	if withEntropy && c.needEntropy && r != nil && size >= 0 {
		features.Entropy, features.EntropyKnown = EntropyFromReaderAt(r, size)
	}
	return features
}
