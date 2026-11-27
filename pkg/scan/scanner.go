package scan

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/deepfence/match-scanner/pkg/extractor"
	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog/log"
)

func New(
	hostMountPath string,
	extractorConfig cfg.Config,
	yaraScannerIn *yara.Scanner,
	scanID string) *Scanner {

	obj := Scanner{
		YaraScanner:   yaraScannerIn,
		ScanID:        scanID,
		Filters:       cfg.Config2Filter(extractorConfig),
		hostMountPath: hostMountPath,
		Engine:        NewLegacyEngine(yaraScannerIn),
	}
	return &obj
}

// NewWithEngine creates a scanner backed by a sharded or legacy engine.
func NewWithEngine(hostMountPath string, extractorConfig cfg.Config, engine *Engine, scanID string) *Scanner {
	return &Scanner{
		ScanID:        scanID,
		Filters:       cfg.Config2Filter(extractorConfig),
		hostMountPath: hostMountPath,
		Engine:        engine,
	}
}

type Scanner struct {
	hostMountPath string
	YaraScanner   *yara.Scanner
	ScanID        string
	Engine        *Engine

	Filters cfg.Filters
}

type ScanType int

const (
	DirScan ScanType = iota
	ImageScan
	ContainerScan
	TarScan
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DirScan:
		return "host"
	case ImageScan:
		return "image"
	case ContainerScan:
		return "container"
	case TarScan:
		return "tar"
	}
	return ""
}

func IsExecAll(mode os.FileMode) bool {
	return mode&0111 == 0111
}

func (s *Scanner) Scan(ctx *tasks.ScanContext, stype ScanType, namespace, id string, scanID string, outputFn func(output.IOCFound, string)) error {
	var (
		extract extractor.FileExtractor
		err     error
	)
	switch stype {
	case DirScan:
		extract, err = extractor.NewDirectoryExtractor(s.Filters, id, true)
	case ImageScan:
		extract, err = extractor.NewImageExtractor(s.Filters, namespace, id)
	case ContainerScan:
		extract, err = extractor.NewContainerExtractor(s.Filters, namespace, id)
	case TarScan:
		extract, err = extractor.NewTarExtractor(s.Filters, namespace, id)
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	if s.Engine == nil {
		return fmt.Errorf("scan engine is not initialized")
	}
	s.Engine.Start()

	workers := s.Engine.Workers()
	type scanJob struct {
		seq  int
		file extractor.ExtractedFile
	}
	type scanResult struct {
		seq  int
		iocs []output.IOCFound
	}
	jobs := make(chan scanJob, workers*2)
	results := make(chan scanResult, workers*2)

	var producerWG sync.WaitGroup
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		defer close(jobs)
		seq := 0
		for {
			if ctx != nil && ctx.Context != nil {
				select {
				case <-ctx.Context.Done():
					return
				default:
				}
			}
			file, nextErr := extract.NextFile()
			if nextErr == io.EOF {
				return
			}
			if nextErr != nil {
				log.Warn().Err(nextErr).Msg("extract file error")
				continue
			}
			select {
			case jobs <- scanJob{seq: seq, file: file}:
				seq++
			case <-ctxDone(ctx):
				file.Close()
				return
			}
		}
	}()

	var workerWG sync.WaitGroup
	workerWG.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer workerWG.Done()
			for job := range jobs {
				file := job.file
				if ctx != nil {
					if err := ctx.Checkpoint("scan_phase"); err != nil {
						file.Close()
						results <- scanResult{seq: job.seq}
						continue
					}
				}
				if s.Filters.SkipNonExecutable && !IsExecAll(file.FilePermissions) {
					log.Debug().Str("file", file.Filename).Msg("Skipping non-executable file")
					file.Close()
					results <- scanResult{seq: job.seq}
					continue
				}

				var found []output.IOCFound
				if err := ScanFile(s, file.Filename, file.Content, file.ContentSize, &found, ""); err != nil {
					log.Warn().Err(err).Str("file", file.Filename).Msg("scan file error")
				}
				file.Close()
				results <- scanResult{seq: job.seq, iocs: found}
			}
		}()
	}

	go func() {
		producerWG.Wait()
		workerWG.Wait()
		close(results)
	}()

	nextSeq := 0
	pending := make(map[int][]output.IOCFound)
	for result := range results {
		pending[result.seq] = result.iocs
		for {
			malwares, ok := pending[nextSeq]
			if !ok {
				break
			}
			delete(pending, nextSeq)
			nextSeq++
			for _, malware := range malwares {
				outputFn(malware, scanID)
			}
		}
	}
	s.Engine.LogStats()
	return nil
}

func ctxDone(ctx *tasks.ScanContext) <-chan struct{} {
	if ctx == nil || ctx.Context == nil {
		return nil
	}
	return ctx.Context.Done()
}
