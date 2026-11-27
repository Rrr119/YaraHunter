package scan

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/yararules"
	yara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog/log"
)

const scanBlockSize = 32 * 1024 * 1024

// EngineOptions controls file-level and shard-level concurrency.
type EngineOptions struct {
	Workers       int
	Shadow        bool
	Prefilter     bool
	EnableEntropy bool
}

// EngineStats is a snapshot of scan activity.
type EngineStats struct {
	Files         int64
	ShardScans    int64
	ShardSkips    int64
	ShadowMisses  int64
	EntropyChecks int64
	Elapsed       time.Duration
}

type engineCounters struct {
	files         atomic.Int64
	shardScans    atomic.Int64
	shardSkips    atomic.Int64
	shadowMisses  atomic.Int64
	entropyChecks atomic.Int64
}

// Engine scans one file using either the legacy single scanner or rule shards.
type Engine struct {
	legacy         *yara.Scanner
	shards         *yararules.ShardSet
	workers        int
	shadow         bool
	prefilter      bool
	entropyEnabled bool
	sem            chan struct{}
	counter        engineCounters
	start          time.Time
}

// NewLegacyEngine wraps the existing single-ruleset scanner.
func NewLegacyEngine(scanner *yara.Scanner) *Engine {
	return &Engine{legacy: scanner, workers: 1}
}

// NewShardEngine creates an engine backed by compiled rule shards.
func NewShardEngine(shards *yararules.ShardSet, opts EngineOptions) *Engine {
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	return &Engine{
		shards:         shards,
		workers:        workers,
		shadow:         opts.Shadow,
		prefilter:      opts.Prefilter,
		entropyEnabled: opts.EnableEntropy,
		sem:            make(chan struct{}, workers),
	}
}

// Workers returns the configured file concurrency.
func (e *Engine) Workers() int {
	if e == nil || e.workers < 1 {
		return 1
	}
	return e.workers
}

// Start marks the beginning of a scan for elapsed-time reporting.
func (e *Engine) Start() {
	e.start = time.Now()
}

// Stats returns a consistent snapshot of counters.
func (e *Engine) Stats() EngineStats {
	if e == nil {
		return EngineStats{}
	}
	elapsed := time.Duration(0)
	if !e.start.IsZero() {
		elapsed = time.Since(e.start)
	}
	return EngineStats{
		Files:         e.counter.files.Load(),
		ShardScans:    e.counter.shardScans.Load(),
		ShardSkips:    e.counter.shardSkips.Load(),
		ShadowMisses:  e.counter.shadowMisses.Load(),
		EntropyChecks: e.counter.entropyChecks.Load(),
		Elapsed:       elapsed,
	}
}

// LogStats writes the counters collected by the engine.
func (e *Engine) LogStats() {
	stats := e.Stats()
	log.Info().
		Int64("files", stats.Files).
		Int64("shard_scans", stats.ShardScans).
		Int64("shard_skips", stats.ShardSkips).
		Int64("prefilter_skips", stats.ShardSkips).
		Int64("shadow_misses", stats.ShadowMisses).
		Int64("entropy_checks", stats.EntropyChecks).
		Dur("scan_elapsed", stats.Elapsed).
		Bool("prefilter_shadow", e.shadow).
		Msg("scan engine stats")
}

// ScanReader scans one file. displayName is used in output after host mount
// path normalization.
func (e *Engine) ScanReader(matchName, displayName string, r io.ReaderAt, size int64, layer string) ([]output.IOCFound, error) {
	e.counter.files.Add(1)
	if e.legacy != nil {
		matches, err := scanOnce(e.legacy, matchName, r, size)
		if err != nil {
			return nil, err
		}
		return matchesToIOCs(matches, displayName, layer), nil
	}
	if e.shards == nil {
		return nil, fmt.Errorf("scan engine is not initialized")
	}
	return e.scanShards(matchName, displayName, r, size, layer)
}

func (e *Engine) scanShards(matchName, displayName string, r io.ReaderAt, size int64, layer string) ([]output.IOCFound, error) {
	features := e.shards.Classifier.ExtractFeaturesWithEntropy(matchName, r, size, e.entropyEnabled)
	if features.EntropyKnown {
		e.counter.entropyChecks.Add(1)
	}
	candidates := e.shards.Candidates(features)
	run := candidates
	skip := 0
	if !e.prefilter {
		run = e.shards.AllShards()
		candidates = run
	} else {
		skip = len(e.shards.Shards) - len(candidates)
	}
	if e.shadow {
		run = e.shards.AllShards()
	}
	e.counter.shardSkips.Add(int64(skip))

	type shardResult struct {
		index   int
		matches yara.MatchRules
		err     error
	}
	results := make([]shardResult, 0, len(run))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, shardIndex := range run {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			e.sem <- struct{}{}
			defer func() { <-e.sem }()

			shard := e.shards.Shard(index)
			scanner, err := shard.NewScanner()
			if err != nil {
				mu.Lock()
				results = append(results, shardResult{index: index, err: err})
				mu.Unlock()
				return
			}
			matches, err := scanOnce(scanner, matchName, r, size)
			shard.PutScanner(scanner)
			e.counter.shardScans.Add(1)

			reportableMatches := 0
			if e.shadow && e.prefilter && err == nil && !containsIndex(candidates, index) {
				for _, match := range matches {
					if shard.Reportable[match.Rule] {
						reportableMatches++
					}
				}
			}
			if reportableMatches > 0 {
				e.counter.shadowMisses.Add(1)
				log.Warn().
					Str("file", matchName).
					Str("shard", shard.Name).
					Int("matches", reportableMatches).
					Msg("prefilter shadow mode: skipped shard would have matched")
			}

			mu.Lock()
			results = append(results, shardResult{index: index, matches: matches, err: err})
			mu.Unlock()
		}(shardIndex)
	}
	wg.Wait()

	var all yara.MatchRules
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}
		shard := e.shards.Shard(result.index)
		for _, match := range result.matches {
			if !shard.Reportable[match.Rule] {
				continue
			}
			all = append(all, match)
		}
	}

	sort.SliceStable(all, func(i, j int) bool {
		oi, oki := e.shards.RuleOrder[all[i].Rule]
		oj, okj := e.shards.RuleOrder[all[j].Rule]
		if oki && okj && oi != oj {
			return oi < oj
		}
		return all[i].Rule < all[j].Rule
	})
	return matchesToIOCs(all, displayName, layer), nil
}

func containsIndex(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func scanOnce(scanner *yara.Scanner, fileName string, r io.ReaderAt, size int64) (yara.MatchRules, error) {
	var matches yara.MatchRules
	scanner.SetCallback(&matches)
	if err := defineScanVariables(scanner, fileName); err != nil {
		return nil, err
	}
	it := newStreamIterator(r, size, scanBlockSize)
	if err := scanner.ScanMemBlocks(it); err != nil {
		return nil, err
	}
	return matches, nil
}

func defineScanVariables(scanner *yara.Scanner, fileName string) error {
	variables := []struct {
		name  string
		value interface{}
	}{
		{"filename", filepath.ToSlash(filepath.Base(fileName))},
		{"filepath", filepath.ToSlash(fileName)},
		{"extension", filepath.Ext(fileName)},
	}
	for _, variable := range variables {
		if err := scanner.DefineVariable(variable.name, variable.value); err != nil {
			return err
		}
	}
	return nil
}

type streamIterator struct {
	r         io.ReaderAt
	size      int64
	blockSize int
	offset    int64
	length    int
}

func newStreamIterator(r io.ReaderAt, size int64, blockSize int) *streamIterator {
	if size < 0 {
		size = 0
	}
	if blockSize <= 0 {
		blockSize = scanBlockSize
	}
	return &streamIterator{r: r, size: size, blockSize: blockSize}
}

func (s *streamIterator) Filesize() uint64 {
	if s.size < 0 {
		return 0
	}
	return uint64(s.size)
}

func (s *streamIterator) First() *yara.MemoryBlock {
	s.offset = 0
	s.length = s.blockSize
	if int64(s.length) > s.size {
		s.length = int(s.size)
	}
	return &yara.MemoryBlock{
		Base:      0,
		Size:      uint64(s.length),
		FetchData: s.fetch,
	}
}

func (s *streamIterator) Next() *yara.MemoryBlock {
	s.offset += int64(s.length)
	if s.offset >= s.size {
		return nil
	}
	s.length = s.blockSize
	if remaining := s.size - s.offset; int64(s.length) > remaining {
		s.length = int(remaining)
	}
	return &yara.MemoryBlock{
		Base:      uint64(s.offset),
		Size:      uint64(s.length),
		FetchData: s.fetch,
	}
}

func (s *streamIterator) fetch(buf []byte) {
	n, _ := s.r.ReadAt(buf, s.offset)
	if n < len(buf) {
		for i := n; i < len(buf); i++ {
			buf[i] = 0
		}
	}
}

// readerAtFromReadSeeker adapts the extractor's io.ReadSeeker to io.ReaderAt.
// Most extractors return *os.File, which is already a ReaderAt.
func readerAtFromReadSeeker(f io.ReadSeeker, size int64) (io.ReaderAt, int64, func(), error) {
	if f == nil {
		return nil, 0, func() {}, fmt.Errorf("nil file content")
	}
	if ra, ok := f.(io.ReaderAt); ok {
		pos, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, 0, func() {}, err
		}
		end, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, 0, func() {}, err
		}
		_, _ = f.Seek(pos, io.SeekStart)
		size = end
		return ra, size, func() {}, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, func() {}, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, func() {}, err
	}
	return bytes.NewReader(data), int64(len(data)), func() {}, nil
}

func matchesToIOCs(matches yara.MatchRules, fileName, layer string) []output.IOCFound {
	totalMatches := 0
	iocsFound := make([]output.IOCFound, 0, len(matches))
	for _, match := range matches {
		stringMatches := make([]output.StringMatch, 0, len(match.Strings))
		for _, str := range match.Strings {
			stringMatches = append(stringMatches, output.StringMatch{
				Offset: int(str.Base) + int(str.Offset),
				Data:   string(str.Data),
			})
		}
		totalMatches += len(match.Strings)

		matchesMetaData := make([]string, len(match.Metas))
		for _, strMeta := range match.Metas {
			matchesMetaData = append(matchesMetaData, fmt.Sprintf("%v : %v \n", strMeta.Identifier, strMeta.Value))
		}
		iocsFound = append(iocsFound, output.IOCFound{
			RuleName:         match.Rule,
			CategoryName:     match.Tags,
			Meta:             matchesMetaData,
			CompleteFilename: fileName,
			Matches:          stringMatches,
		})
	}

	updatedSeverity, updatedScore := calculateSeverity(totalMatches, "low", 0)
	if len(matches) == 0 {
		return iocsFound
	}
	for idx := range iocsFound {
		ioc := iocsFound[idx]
		ioc.FileSeverity = updatedSeverity
		ioc.FileSevScore = updatedScore
		ioc.LayerID = layer
		summary := ""
		class := "Undefined"
		ioc.MetaRules = make(map[string]string)
		for _, meta := range ioc.Meta {
			metaSplit := strings.Split(meta, " = ")
			if len(metaSplit) <= 1 {
				continue
			}
			ioc.MetaRules[metaSplit[0]] = strings.ReplaceAll(metaSplit[1], "\n", "")
			switch metaSplit[0] {
			case "description":
				summary += "The file has a rule match that " + strings.ReplaceAll(metaSplit[1], "\n", "") + "."
			case "sev":
				ioc.FileSeverity = strings.TrimSpace(strings.ReplaceAll(metaSplit[1], "\n", ""))
				ioc.FileSevScore = getSeverityScore(ioc.FileSeverity)
			case "info":
				class = strings.TrimSpace(strings.ReplaceAll(metaSplit[1], "\n", ""))
			default:
				if len(metaSplit[0]) > 0 {
					summary += "The matched rule file's " + metaSplit[0] + " is" + strings.ReplaceAll(metaSplit[1], "\n", "") + "."
				}
			}
		}
		ioc.Summary = summary
		ioc.Class = class
		iocsFound[idx] = ioc
	}
	return iocsFound
}
