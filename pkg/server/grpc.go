package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/deepfence/YaraHunter/constants"
	"github.com/deepfence/YaraHunter/pkg/jobs"
	"github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/scan"
	yararules "github.com/deepfence/YaraHunter/pkg/yararules"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	tasks "github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	cfg "github.com/deepfence/match-scanner/pkg/config"
)

var (
	MalwareScanDir          = "/"
	HostMountDir            = "/fenced/mnt/host"
	cntnrPathPrefixRegex    = `.+?\/overlay2\/[A-z0-9a-z]+\/[a-z]+\/`
	cntnrPathPrefixRegexObj *regexp.Regexp
)

func init() {
	if os.Getenv("DF_SERVERLESS") == "true" {
		MalwareScanDir = "/"
	} else {
		MalwareScanDir = HostMountDir
	}
	cntnrPathPrefixRegexObj = regexp.MustCompile(cntnrPathPrefixRegex)
}

type GRPCScannerServer struct {
	HostMountPath, SocketPath string
	InactiveThreshold         int
	ExtractorConfig           cfg.Config
	YaraRules                 *yararules.YaraRules
	ShardSet                  *yararules.ShardSet
	ScanOptions               ScanOptions
	pluginName                string
	pb.UnimplementedAgentPluginServer
	pb.UnimplementedScannersServer
	ScanMap sync.Map
}

// ScanOptions controls optional parallel scanning in long-lived server mode.
type ScanOptions struct {
	RuleShards          int
	WorkersPerScan      int
	Prefilter           bool
	PrefilterShadow     bool
	EnableEntropyFilter bool
}

type MalwareRPCServer struct {
	*GRPCScannerServer
	pb.UnimplementedMalwareScannerServer
}

func (s *GRPCScannerServer) ReportJobsStatus(context.Context, *pb.Empty) (*pb.JobReports, error) {
	return &pb.JobReports{
		RunningJobs: jobs.GetRunningJobCount(),
	}, nil
}

func (s *GRPCScannerServer) StopScan(c context.Context, req *pb.StopScanRequest) (*pb.StopScanResult, error) {
	scanID := req.ScanId
	result := &pb.StopScanResult{
		Success:     true,
		Description: "",
	}

	obj, found := s.ScanMap.Load(scanID)
	if !found {
		msg := "Failed to Stop scan"
		log.Info().Str("scan_id", scanID).Msg(msg + ", may have already completed")
		result.Success = false
		result.Description = "Failed to Stop scan"
		return result, nil
	} else {
		msg := "Stop request submitted"
		log.Info().Str("scan_id", scanID).Msg(msg)
		result.Success = true
		result.Description = msg
	}

	scanContext := obj.(*tasks.ScanContext)
	scanContext.StopTriggered.Store(true)
	scanContext.Cancel()

	return result, nil
}

func (s *GRPCScannerServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name{Str: s.pluginName}, nil
}

func (s *GRPCScannerServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid{Str: fmt.Sprintf("%s-%s", s.pluginName, s.SocketPath)}, nil
}

func (s *MalwareRPCServer) FindMalwareInfo(c context.Context, r *pb.MalwareRequest) (*pb.MalwareResult, error) {
	var engine *scan.Engine
	if s.ShardSet != nil {
		engine = scan.NewShardEngine(s.ShardSet, scan.EngineOptions{
			Workers:       s.ScanOptions.WorkersPerScan,
			Shadow:        s.ScanOptions.PrefilterShadow,
			Prefilter:     s.ScanOptions.Prefilter,
			EnableEntropy: s.ScanOptions.EnableEntropyFilter,
		})
	} else {
		yaraScanner, err := s.YaraRules.NewScanner()
		if err != nil {
			return &pb.MalwareResult{}, err
		}
		engine = scan.NewLegacyEngine(yaraScanner)
	}

	go func() {
		log.Info().Interface("request", r).Msg("request to scan")

		namespace := ""
		container := ""
		image := ""
		path := ""
		switch {
		case r.GetContainer() != nil:
			namespace = r.GetContainer().GetNamespace()
			container = r.GetContainer().GetId()
		case r.GetImage() != nil:
			image = r.GetImage().GetName()
		default:
			path = r.GetPath()
		}

		DoScanWithEngine(
			r.ScanId,
			s.HostMountPath,
			s.ExtractorConfig,
			s.InactiveThreshold,
			&s.ScanMap,
			namespace,
			path,
			image,
			container,
			engine,
			func(res output.IOCFound, scanID string) {
				output.WriteScanData([]*pb.MalwareInfo{output.MalwaresToMalwareInfo(res)}, scanID)
			},
		)
	}()
	return &pb.MalwareResult{}, nil
}

func DoScan(
	scanID string,
	hostMountPath string,
	ExtractorConfig cfg.Config,
	inactiveThreshold int,
	ScanMap *sync.Map,
	namespace,
	path, image, container string,
	yaraScanner *yara.Scanner, writeToFile func(res output.IOCFound, scanID string)) {
	DoScanWithEngine(
		scanID,
		hostMountPath,
		ExtractorConfig,
		inactiveThreshold,
		ScanMap,
		namespace,
		path,
		image,
		container,
		scan.NewLegacyEngine(yaraScanner),
		writeToFile,
	)
}

// DoScanWithEngine runs a scan using the supplied engine.
func DoScanWithEngine(
	scanID string,
	hostMountPath string,
	ExtractorConfig cfg.Config,
	inactiveThreshold int,
	ScanMap *sync.Map,
	namespace,
	path, image, container string,
	engine *scan.Engine, writeToFile func(res output.IOCFound, scanID string)) {

	jobs.StartScanJob()
	defer jobs.StopScanJob()

	scanner := scan.NewWithEngine(hostMountPath, ExtractorConfig, engine, scanID)
	res, ctx := tasks.StartStatusReporter(
		scanID,
		func(status tasks.ScanStatus) error {
			output.WriteScanStatus(status.ScanStatus, status.ScanId, status.ScanMessage)
			return nil
		},
		tasks.StatusValues{
			IN_PROGRESS: "IN_PROGRESS",
			CANCELLED:   "CANCELLED",
			FAILED:      "ERROR",
			SUCCESS:     "COMPLETE",
		},
		time.Duration(inactiveThreshold)*time.Second)
	ScanMap.Store(scanner.ScanID, ctx)
	var err error
	defer func() {
		ScanMap.Delete(scanner.ScanID)
		res <- err
		close(res)
	}()

	switch {
	case path != "":
		log.Info().Str("path", path).Msg("scan for malwares in path")
		err = scanner.Scan(ctx, scan.DirScan, "", path, scanID, writeToFile)
	case image != "":
		log.Info().Str("image", image).Msg("scan for malwares in image")
		err = scanner.Scan(ctx, scan.ImageScan, "", image, scanID, writeToFile)
	case container != "":
		log.Info().Str("container", container).Msg("scan for malwares in container")
		err = scanner.Scan(ctx, scan.ContainerScan, namespace, container, scanID, writeToFile)
	default:
		err = fmt.Errorf("invalid request")
	}

	if err != nil {
		log.Error().Err(err).Msg("scan error")
	}
}

func NewGRPCScannerServer(
	hostMoundPath, socketPath, rulesPath string,
	InactiveThreshold int,
	failOnCompileWarning bool,
	config cfg.Config, pluginName string,
	options ...ScanOptions,
) (*GRPCScannerServer, error) {
	scanOpts := ScanOptions{
		RuleShards:          1,
		WorkersPerScan:      runtime.NumCPU(),
		Prefilter:           true,
		EnableEntropyFilter: true,
	}
	if len(options) > 0 {
		scanOpts = options[0]
		if scanOpts.WorkersPerScan <= 0 {
			scanOpts.WorkersPerScan = runtime.NumCPU()
		}
	}
	yaraRules := yararules.New(rulesPath)
	var shardSet *yararules.ShardSet
	if scanOpts.RuleShards > 1 {
		set, err := yaraRules.CompileShards(scanOpts.RuleShards, failOnCompileWarning)
		if err == nil {
			shardSet = set
		} else {
			log.Warn().Err(err).Msg("rule sharding failed, falling back to the legacy single ruleset scanner")
		}
	}
	if shardSet == nil {
		if err := yaraRules.Compile(constants.Filescan, failOnCompileWarning); err != nil {
			return nil, err
		}
	}
	res := &GRPCScannerServer{
		HostMountPath:                  hostMoundPath,
		SocketPath:                     socketPath,
		InactiveThreshold:              InactiveThreshold,
		ExtractorConfig:                config,
		YaraRules:                      yaraRules,
		ShardSet:                       shardSet,
		ScanOptions:                    scanOpts,
		pluginName:                     pluginName,
		UnimplementedAgentPluginServer: pb.UnimplementedAgentPluginServer{},
		UnimplementedScannersServer:    pb.UnimplementedScannersServer{},
		ScanMap:                        sync.Map{},
	}

	return res, nil
}

func RunGrpcServer(ctx context.Context,
	socketPath string,
	impl any,
	customImpl func(s grpc.ServiceRegistrar, impl any)) error {

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	s := grpc.NewServer()

	if err != nil {
		return err
	}

	pb.RegisterAgentPluginServer(s, impl.(pb.AgentPluginServer))
	pb.RegisterScannersServer(s, impl.(pb.ScannersServer))
	customImpl(s, impl)

	log.Info().Str("addr", lis.Addr().String()).Msg("main: server listening")
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Error().Err(err).Msg("server error")
		}
	}()

	<-ctx.Done()
	s.GracefulStop()

	log.Info().Msg("main: exiting gracefully")
	return nil
}
