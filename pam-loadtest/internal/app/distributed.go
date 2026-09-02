package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/distributed"
	"pam-loadtest/internal/pam"
	"pam-loadtest/internal/runreport"
)

var BuildVersion = "dev"

func applyRequestRuntimePolicy(cfg *config.Config, request distributed.RunRequest) {
	cfg.SSHActivityInterval = time.Duration(request.SSHActivityIntervalNanos)
	cfg.SSHActivityMode = request.SSHActivityMode
	cfg.GraphicalActivityIntervals = make(map[config.Protocol]time.Duration, len(request.GraphicalActivityIntervalNanos))
	for protocol, nanos := range request.GraphicalActivityIntervalNanos {
		cfg.GraphicalActivityIntervals[config.Protocol(protocol)] = time.Duration(nanos)
	}
	cfg.ContinueOnErrors = request.ContinueOnErrors
	cfg.ConnectionOnly = request.ConnectionOnly
	cfg.ConnectRetries = request.ConnectRetries
}

func graphicalActivityIntervalNanos(cfg config.Config) map[string]int64 {
	values := make(map[string]int64, len(cfg.GraphicalActivityIntervals))
	for protocol, interval := range cfg.GraphicalActivityIntervals {
		values[string(protocol)] = int64(interval)
	}
	return values
}

func RunAgent(ctx context.Context, configPath, listenAddress, token string, capacity int, opts LocalOptions) error {
	if token == "" {
		return fmt.Errorf("PAM_AGENT_TOKEN is required")
	}
	if capacity < 1 {
		return fmt.Errorf("agent capacity must be positive")
	}
	base, err := config.Load(configPath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	capabilities := distributed.Capabilities{
		Version: BuildVersion, Capacity: capacity, DirectCapacity: opts.DirectCapacity,
		BrowserCapacity: opts.BrowserWorkers * opts.SessionsPerWorker,
		DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"},
	}
	if capabilities.DirectCapacity <= 0 {
		capabilities.DirectCapacity = capacity
	}
	registry := distributed.NewRegistryWithCapabilitiesAndContext(ctx, capabilities, func(runCtx context.Context, request distributed.RunRequest) (runreport.Report, error) {
		cfg := base
		applyRequestRuntimePolicy(&cfg, request)
		cfg.Total = len(request.Jobs)
		cfg.Ramp = time.Duration(request.RampNanos)
		cfg.Hold = time.Duration(request.HoldNanos)
		cfg.Seed = request.Seed
		cfg.Protocols = map[config.Protocol]int{}
		cfg.ExecutionModes = map[config.Protocol]config.ModeCounts{}
		jobs := make([]config.Job, len(request.Jobs))
		for index, job := range request.Jobs {
			protocol := config.Protocol(job.Protocol)
			mode := config.ExecutionMode(job.Mode)
			cfg.Protocols[protocol]++
			counts := cfg.ExecutionModes[protocol]
			if mode == config.Browser {
				counts.Browser++
			} else {
				counts.Direct++
			}
			cfg.ExecutionModes[protocol] = counts
			jobs[index] = config.Job{ID: job.ID, Protocol: protocol, Mode: mode, AssetID: job.AssetID, AccountID: job.AccountID}
		}
		if _, err := cfg.Expand(); err != nil {
			return runreport.Report{}, err
		}
		runOpts := opts
		runOpts.PAMToken = request.PAMToken
		runOpts.PAMCookies = requestPAMCookies(request.PAMCookies)
		return RunConfigJobs(runCtx, cfg, jobs, request.RunID, runOpts)
	})
	server := distributed.NewAgentServerWithCapabilities(token, capabilities, registry)
	go func() { <-ctx.Done(); server.GracefulStop(); _ = listener.Close() }()
	err = server.Serve(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func RunController(ctx context.Context, configPath string, addresses []string, token string) (runreport.Report, error) {
	if token == "" {
		return runreport.Report{}, fmt.Errorf("PAM_AGENT_TOKEN is required")
	}
	manifestPath := os.Getenv("PAM_ASSET_MANIFEST")
	if manifestPath == "" {
		return runreport.Report{}, fmt.Errorf("PAM_ASSET_MANIFEST is required for controller mode")
	}
	grace, err := controllerGrace()
	if err != nil {
		return runreport.Report{}, err
	}
	startDelay, err := agentStartDelay()
	if err != nil {
		return runreport.Report{}, err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return runreport.Report{}, err
	}
	if err := applyRuntimeOverrides(&cfg); err != nil {
		return runreport.Report{}, err
	}
	sharedPAMAuth, err := controllerSharedPAMAuth(ctx, cfg)
	if err != nil {
		return runreport.Report{}, err
	}
	jobs, err := cfg.Expand()
	if err != nil {
		return runreport.Report{}, err
	}
	jobs, err = prepareManifestJobs(jobs, manifestPath, cfg.Seed)
	if err != nil {
		return runreport.Report{}, err
	}
	agents := make([]distributed.Agent, 0, len(addresses))
	clients := map[string]*distributed.AgentClient{}
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	version := ""
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		client, err := distributed.DialAgent(ctx, address, func(ctx context.Context, target string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", target)
		}, token)
		if err != nil {
			return runreport.Report{}, err
		}
		health, err := client.Health(ctx)
		if err != nil {
			_ = client.Close()
			return runreport.Report{}, fmt.Errorf("agent %s health: %w", address, err)
		}
		capabilities := health.Capabilities
		if capabilities.Version == "" || capabilities.Capacity < 1 || capabilities.DirectCapacity < 1 || len(capabilities.DirectProtocols) == 0 {
			_ = client.Close()
			return runreport.Report{}, fmt.Errorf("agent %s returned incomplete capabilities", address)
		}
		if capabilities.Version != BuildVersion {
			_ = client.Close()
			return runreport.Report{}, fmt.Errorf("agent %s version does not match controller", address)
		}
		if version == "" {
			version = capabilities.Version
		} else if capabilities.Version != version {
			_ = client.Close()
			return runreport.Report{}, fmt.Errorf("agent %s version mismatch", address)
		}
		directProtocols := make([]config.Protocol, len(capabilities.DirectProtocols))
		for index, protocol := range capabilities.DirectProtocols {
			directProtocols[index] = config.Protocol(protocol)
		}
		agents = append(agents, distributed.Agent{ID: address, Capacity: capabilities.Capacity, DirectCapacity: capabilities.DirectCapacity, BrowserCapacity: capabilities.BrowserCapacity, DirectProtocols: directProtocols})
		clients[address] = client
	}
	if len(agents) == 0 {
		return runreport.Report{}, fmt.Errorf("PAM_AGENTS must list at least one agent")
	}
	assignments, err := distributed.Partition(jobs, agents)
	if err != nil {
		return runreport.Report{}, err
	}
	runID := fmt.Sprintf("%s-%d", cfg.Name, time.Now().UnixNano())
	started := make([]string, 0, len(agents))
	expected := make(map[string][]config.Job)
	cancelStarted := func(cancelCtx context.Context) error {
		var firstErr error
		for _, address := range started {
			if _, err := clients[address].Cancel(cancelCtx, distributed.CancelRequest{RunID: runID}); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("agent %s cancel: %w", address, err)
			}
		}
		return firstErr
	}
	cancelStartedBeforeReturn := func() {
		cancelCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cancelStarted(cancelCtx)
	}
	for _, agent := range agents {
		if len(started) > 0 && startDelay > 0 {
			select {
			case <-ctx.Done():
				cancelStartedBeforeReturn()
				return runreport.Report{}, ctx.Err()
			case <-time.After(startDelay):
			}
		}
		address := agent.ID
		assigned := assignments[address]
		if len(assigned) == 0 {
			continue
		}
		wire := make([]distributed.WireJob, len(assigned))
		for i, job := range assigned {
			wire[i] = distributed.WireJob{ID: job.ID, Protocol: string(job.Protocol), Mode: string(job.Mode), AssetID: job.AssetID, AccountID: job.AccountID}
		}
		response, err := clients[address].Start(ctx, distributed.RunRequest{RunID: runID, PAMToken: sharedPAMAuth.Token, PAMCookies: sharedPAMAuth.Cookies, RampNanos: int64(cfg.Ramp), HoldNanos: int64(cfg.Hold), SSHActivityIntervalNanos: int64(cfg.SSHActivityInterval), SSHActivityMode: cfg.SSHActivityMode, GraphicalActivityIntervalNanos: graphicalActivityIntervalNanos(cfg), ContinueOnErrors: cfg.ContinueOnErrors, ConnectionOnly: cfg.ConnectionOnly, ConnectRetries: cfg.ConnectRetries, Seed: cfg.Seed, Jobs: wire})
		if err != nil {
			cancelStartedBeforeReturn()
			return runreport.Report{}, fmt.Errorf("agent %s start: %w", address, err)
		}
		started = append(started, address)
		if response.RunID != runID || response.Accepted != len(assigned) {
			cancelStartedBeforeReturn()
			return runreport.Report{}, fmt.Errorf("agent %s start acknowledgement mismatch", address)
		}
		expected[address] = assigned
	}
	waitCtx, cancel := context.WithTimeout(ctx, cfg.Ramp+cfg.Hold+grace)
	defer cancel()
	pollCtx := waitCtx
	var cleanupCancel context.CancelFunc
	defer func() {
		if cleanupCancel != nil {
			cleanupCancel()
		}
	}()
	reports := make(map[string]runreport.Report, len(started))
	terminalStatus := ""
	var primaryErr error
	cleanupStarted := false
	setTerminalStatus := func(status string) {
		if status == string(distributed.Failed) || terminalStatus == "" {
			terminalStatus = status
		}
	}
	beginCleanup := func(status string, cause error) {
		setTerminalStatus(status)
		if cause != nil && primaryErr == nil {
			primaryErr = cause
		}
		if cleanupStarted {
			return
		}
		cleanupStarted = true
		pollCtx, cleanupCancel = context.WithTimeout(context.Background(), grace)
		if err := cancelStarted(pollCtx); err != nil && primaryErr == nil {
			primaryErr = err
		}
	}
	for len(reports) < len(started) {
		for _, address := range started {
			if _, complete := reports[address]; complete {
				continue
			}
			statusResponse, statusErr := clients[address].Status(pollCtx, distributed.StatusRequest{RunID: runID})
			if statusErr != nil {
				beginCleanup(string(distributed.Failed), fmt.Errorf("agent %s status: %w", address, statusErr))
				continue
			}
			switch statusResponse.Status {
			case distributed.Pending, distributed.Running:
			case distributed.Completed:
				if statusResponse.Report == nil {
					beginCleanup(string(distributed.Failed), fmt.Errorf("agent %s terminal report is missing", address))
					continue
				}
				reports[address] = *statusResponse.Report
			case distributed.Failed, distributed.Cancelled:
				if statusResponse.Report == nil {
					beginCleanup(string(distributed.Failed), fmt.Errorf("agent %s terminal report is missing", address))
					continue
				}
				reports[address] = *statusResponse.Report
				beginCleanup(string(statusResponse.Status), nil)
			default:
				beginCleanup(string(distributed.Failed), fmt.Errorf("agent %s returned an invalid status", address))
			}
		}
		if len(reports) == len(started) {
			break
		}
		select {
		case <-pollCtx.Done():
			if cleanupStarted {
				return runreport.Report{}, fmt.Errorf("controller cleanup failed before all terminal reports were collected: %w", pollCtx.Err())
			}
			status := string(distributed.Failed)
			if ctx.Err() != nil {
				status = string(distributed.Cancelled)
			}
			beginCleanup(status, fmt.Errorf("controller wait failed: %w", pollCtx.Err()))
		case <-time.After(100 * time.Millisecond):
		}
	}
	if terminalStatus != "" || primaryErr != nil {
		aggregated, aggregateErr := runreport.AggregateTerminalForBuild(runID, BuildVersion, expected, reports, terminalStatus)
		if aggregateErr != nil {
			return runreport.Report{}, aggregateErr
		}
		if primaryErr != nil {
			return aggregated, primaryErr
		}
		return aggregated, fmt.Errorf("distributed run ended with status %s", terminalStatus)
	}
	var aggregated runreport.Report
	if cfg.ConnectionOnly {
		aggregated, err = runreport.AggregateConnectionOnlyForBuild(runID, BuildVersion, expected, reports)
	} else {
		aggregated, err = runreport.AggregateForBuild(runID, BuildVersion, expected, reports)
	}
	if err != nil {
		return runreport.Report{}, err
	}
	return aggregated, nil
}

func controllerGrace() (time.Duration, error) {
	value := os.Getenv("PAM_CONTROLLER_GRACE")
	if value == "" {
		return 2 * time.Minute, nil
	}
	grace, err := time.ParseDuration(value)
	if err != nil || grace <= 0 {
		return 0, fmt.Errorf("PAM_CONTROLLER_GRACE must be a positive duration")
	}
	return grace, nil
}

type sharedPAMAuth struct {
	Token   string
	Cookies []distributed.PAMCookie
}

func controllerSharedPAMAuth(ctx context.Context, cfg config.Config) (sharedPAMAuth, error) {
	if strings.ToLower(strings.TrimSpace(os.Getenv("PAM_SHARE_LOGIN_TOKEN"))) != "true" {
		return sharedPAMAuth{}, nil
	}
	username, password, err := cfg.Credentials()
	if err != nil {
		return sharedPAMAuth{}, err
	}
	client, err := pam.New(cfg.PAM.BaseURL, pam.Options{})
	if err != nil {
		return sharedPAMAuth{}, err
	}
	if err := client.Login(ctx, username, password); err != nil {
		return sharedPAMAuth{}, err
	}
	auth := sharedPAMAuth{Token: client.Token(), Cookies: wirePAMCookies(client.BrowserCookies())}
	if auth.Token == "" && len(auth.Cookies) == 0 {
		return sharedPAMAuth{}, fmt.Errorf("PAM login did not return reusable runtime authentication")
	}
	return auth, nil
}

func wirePAMCookies(cookies []http.Cookie) []distributed.PAMCookie {
	if len(cookies) == 0 {
		return nil
	}
	wire := make([]distributed.PAMCookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		wire = append(wire, distributed.PAMCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
		})
	}
	return wire
}

func requestPAMCookies(cookies []distributed.PAMCookie) []http.Cookie {
	if len(cookies) == 0 {
		return nil
	}
	out := make([]http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		out = append(out, http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
		})
	}
	return out
}

func agentStartDelay() (time.Duration, error) {
	value := os.Getenv("PAM_AGENT_START_DELAY")
	if value == "" {
		return 0, nil
	}
	delay, err := time.ParseDuration(value)
	if err != nil || delay < 0 {
		return 0, fmt.Errorf("PAM_AGENT_START_DELAY must be a non-negative duration")
	}
	return delay, nil
}
