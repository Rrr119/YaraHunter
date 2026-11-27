package scan

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os/exec"
	"strings"
	"syscall"

	"github.com/gabriel-vasile/mimetype"

	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/rs/zerolog/log"
)

var (
	ErrmaxMalwaresExceeded = errors.New("number of secrets exceeded max-secrets")
	execMimeTypes          = []string{"text/x-shellscript", "application/x-executable", "application/x-mach-binary", "application/x-msdownload", "application/exe", "application/x-msdos-program", "application/x-elf", "application/x-sharedlib", "application/x-pie-executable", "application/java-archive", "application/x-java-archive", "text/x-python", "application/x-batch"}
	sharedMimeTypesList    = []string{"application/x-sharedlib"}
)

// Data type to store details about the container image after parsing manifest
type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
	LayerIds []string `json:",omitempty"`
}

var (
	severityToScore = map[string]float64{
		"critical": 10.0,
		"high":     8.0,
		"medium":   5.0,
		"low":      2.0,
	}
)

func getSeverityScore(severity string) float64 {
	if score, ok := severityToScore[severity]; ok {
		return score
	}
	return 0.0
}

func calculateSeverity(lenMatch int, severity string, severityScore float64) (string, float64) {

	updatedSeverity := "low"
	MinIOCLength := 3
	MaxIOCLength := 6

	if lenMatch < MinIOCLength {
		return severity, severityScore
	}

	if lenMatch >= MaxIOCLength {
		return "high", 10.0
	}

	scoreRange := 10.0 - severityScore

	increment := ((float64(lenMatch) - float64(MinIOCLength)) * scoreRange) / (float64(MaxIOCLength) - float64(MinIOCLength))

	updatedScore := severityScore + increment
	if updatedScore > 10.0 {
		updatedScore = 10.0
	}

	if 2.5 < updatedScore && updatedScore <= 7.5 {
		updatedSeverity = "medium"
	} else if 7.5 < updatedScore {
		updatedSeverity = "high"
	}

	return updatedSeverity, math.Round(updatedScore*100) / 100
}

func isSharedLibrary(filePath string) bool {
	mtype, err := mimetype.DetectFile(filePath)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("failed to detect mimetype")
		return false
	}
	for _, execType := range sharedMimeTypesList {
		if mtype.String() == execType {
			return true
		}
	}
	return false
}

func fileMimetypeCheck(filePath string, mimeTypesList []string) bool {
	mtype, err := mimetype.DetectFile(filePath)
	if err != nil {
		log.Error().Err(err).Str("file", filePath).Msg("failed to detect mimetype")
		return false
	}

	for _, execType := range mimeTypesList {
		if strings.Contains(mtype.String(), execType) {
			return true
		}
	}

	return false
}

func isExecutable(path string) bool {
	// todo: add more checks later
	return fileMimetypeCheck(path, execMimeTypes)
}

// ScanFile scans a single file through the scanner's engine. It is kept as a
// compatibility wrapper for callers that scan files directly.
func ScanFile(s *Scanner, fileName string, f io.ReadSeeker, fsize int, iocs *[]output.IOCFound, layer string) error {
	log.Debug().Str("file", fileName).Msg("Scanning file")
	*iocs = (*iocs)[:0]
	if s.Engine == nil {
		if s.YaraScanner == nil {
			return errors.New("scan engine is not initialized")
		}
		s.Engine = NewLegacyEngine(s.YaraScanner)
	}
	reader, size, cleanup, err := readerAtFromReadSeeker(f, int64(fsize))
	if err != nil {
		return err
	}
	defer cleanup()

	displayName := fileName
	if s.hostMountPath != "" {
		displayName = strings.TrimPrefix(displayName, s.hostMountPath)
	}
	found, err := s.Engine.ScanReader(fileName, displayName, reader, size, layer)
	if err != nil {
		return err
	}
	*iocs = append(*iocs, found...)
	return nil
}

// Execute the specified command and return the output
// @parameters
// name - Command to be executed
// args - all the arguments to be passed to the command
// @returns
// string - contents of standard output
// string - contents of standard error
// int - exit code of the executed command
func runCommand(name string, args ...string) (stdout string, stderr string, exitCode int) {
	var defaultFailedCode = 1
	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		// try to get the exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			// This will happen (in OSX) if `name` is not available in $PATH,
			// in this situation, exit code could not be get, and stderr will be
			// empty string very likely, so we use the default fail code, and format err
			// to string and set to stderr
			log.Debug().Str("name", name).Interface("args", args).Msg("Could not get exit code for failed program")
			exitCode = defaultFailedCode
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}
	return
}

type ImageExtractionResult struct {
	IOCs    []output.IOCFound
	ImageID string
}
