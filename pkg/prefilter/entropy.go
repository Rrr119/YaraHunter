package prefilter

import (
	"io"
	"math"
)

const entropySampleSize = 1024 * 1024

// ShannonEntropy returns the Shannon entropy of data in bits per byte.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]uint64
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EntropyFromReaderAt computes the entropy of size bytes without loading the
// whole file. Unknown or short reads are reported as not known so callers can
// fail open (scan the file) instead of creating a false negative.
func EntropyFromReaderAt(r io.ReaderAt, size int64) (float64, bool) {
	if r == nil || size < 0 {
		return 0, false
	}
	if size == 0 {
		return 0, true
	}

	var counts [256]uint64
	buf := make([]byte, entropySampleSize)
	var read int64
	for read < size {
		n := int64(len(buf))
		if remaining := size - read; remaining < n {
			n = remaining
		}
		got, err := r.ReadAt(buf[:n], read)
		if got > 0 {
			for _, b := range buf[:got] {
				counts[b]++
			}
			read += int64(got)
		}
		if err != nil {
			return 0, false
		}
		if got == 0 {
			return 0, false
		}
	}

	total := float64(read)
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy, true
}
