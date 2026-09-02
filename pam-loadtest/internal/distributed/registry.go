package distributed

import (
	"context"
	"fmt"
	"sync"
	"time"

	"pam-loadtest/internal/runreport"
)

type Executor func(context.Context, RunRequest) (runreport.Report, error)

type runRecord struct {
	status          RunStatus
	report          *runreport.Report
	errorText       string
	cancel          context.CancelFunc
	cancelRequested bool
}

type Registry struct {
	mu           sync.Mutex
	capacity     int
	capabilities Capabilities
	execute      Executor
	runs         map[string]*runRecord
	active       string
	parent       context.Context
}

func NewRegistry(capacity int, execute Executor) *Registry {
	return NewRegistryWithCapabilities(Capabilities{Version: "legacy", Capacity: capacity, DirectCapacity: capacity, BrowserCapacity: capacity, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}, execute)
}

func NewRegistryWithContext(parent context.Context, capacity int, execute Executor) *Registry {
	return NewRegistryWithCapabilitiesAndContext(parent, Capabilities{Version: "legacy", Capacity: capacity, DirectCapacity: capacity, BrowserCapacity: capacity, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}, execute)
}

func NewRegistryWithCapabilities(capabilities Capabilities, execute Executor) *Registry {
	return NewRegistryWithCapabilitiesAndContext(context.Background(), capabilities, execute)
}

func NewRegistryWithCapabilitiesAndContext(parent context.Context, capabilities Capabilities, execute Executor) *Registry {
	return &Registry{capacity: capabilities.Capacity, capabilities: capabilities, execute: execute, runs: make(map[string]*runRecord), parent: parent}
}

func (r *Registry) Start(_ context.Context, request RunRequest) (RunResponse, error) {
	if err := validateRunRequest(request, r.capabilities); err != nil {
		return RunResponse{}, err
	}
	r.mu.Lock()
	if _, exists := r.runs[request.RunID]; exists {
		r.mu.Unlock()
		return RunResponse{}, fmt.Errorf("run ID already exists")
	}
	if r.active != "" {
		r.mu.Unlock()
		return RunResponse{}, fmt.Errorf("agent is already running a scenario")
	}
	ctx, cancel := context.WithCancel(r.parent)
	record := &runRecord{status: Running, cancel: cancel}
	r.runs[request.RunID] = record
	r.active = request.RunID
	r.mu.Unlock()
	go func() {
		report, err := r.execute(ctx, request)
		r.mu.Lock()
		defer r.mu.Unlock()
		if record.cancelRequested || ctx.Err() != nil {
			record.status = Cancelled
			report.RunID = request.RunID
			report.Status = string(Cancelled)
			record.report = &report
		} else if err != nil {
			record.status = Failed
			record.errorText = "run execution failed"
			report.RunID = request.RunID
			report.Status = string(Failed)
			record.report = &report
		} else {
			record.status = Completed
			report.RunID = request.RunID
			report.Status = string(Completed)
			record.report = &report
		}
		if r.active == request.RunID {
			r.active = ""
		}
	}()
	return RunResponse{RunID: request.RunID, Accepted: len(request.Jobs), Status: Running}, nil
}

func (r *Registry) Status(_ context.Context, request StatusRequest) (StatusResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.runs[request.RunID]
	if !ok {
		return StatusResponse{}, fmt.Errorf("unknown run ID")
	}
	response := StatusResponse{RunID: request.RunID, Status: record.status, Error: record.errorText}
	if record.report != nil {
		copy := *record.report
		response.Report = &copy
	}
	return response, nil
}

func (r *Registry) Cancel(_ context.Context, request CancelRequest) (CancelResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.runs[request.RunID]
	if !ok {
		return CancelResponse{}, fmt.Errorf("unknown run ID")
	}
	switch record.status {
	case Running, Pending:
		record.cancelRequested = true
		record.cancel()
	}
	status := record.status
	if record.cancelRequested {
		status = Cancelled
	}
	return CancelResponse{RunID: request.RunID, Status: status}, nil
}

func validateRunRequest(request RunRequest, capabilities Capabilities) error {
	if request.RunID == "" {
		return fmt.Errorf("run ID is required")
	}
	if request.RampNanos <= 0 || request.HoldNanos <= 0 {
		return fmt.Errorf("positive ramp and hold durations are required")
	}
	if request.ConnectRetries < 0 || request.ConnectRetries > 3 {
		return fmt.Errorf("connect retries must be between 0 and 3")
	}
	sshActivityInterval := time.Duration(request.SSHActivityIntervalNanos)
	if sshActivityInterval < time.Second || sshActivityInterval > time.Minute || sshActivityInterval%time.Second != 0 {
		return fmt.Errorf("invalid SSH activity interval")
	}
	if request.SSHActivityMode != "" && request.SSHActivityMode != "output" && request.SSHActivityMode != "keepalive" {
		return fmt.Errorf("invalid SSH activity mode")
	}
	for protocol, nanos := range request.GraphicalActivityIntervalNanos {
		if protocol != "rdp" && protocol != "vnc" && protocol != "web" && protocol != "mysql" {
			return fmt.Errorf("invalid graphical activity protocol")
		}
		interval := time.Duration(nanos)
		if interval < time.Second || interval > time.Minute || interval%time.Second != 0 {
			return fmt.Errorf("invalid graphical activity interval")
		}
	}
	if len(request.Jobs) == 0 {
		return fmt.Errorf("at least one job is required")
	}
	if len(request.Jobs) > capabilities.Capacity {
		return fmt.Errorf("job count exceeds agent capacity")
	}
	direct, browser := 0, 0
	supported := make(map[string]struct{}, len(capabilities.DirectProtocols))
	for _, protocol := range capabilities.DirectProtocols {
		supported[protocol] = struct{}{}
	}
	assetIDs := make(map[string]struct{}, len(request.Jobs))
	accountIDs := make(map[string]struct{}, len(request.Jobs))
	jobIDs := make(map[int]struct{}, len(request.Jobs))
	for _, job := range request.Jobs {
		if job.ID < 1 || job.AssetID == "" || job.AccountID == "" {
			return fmt.Errorf("job is missing required bound fields")
		}
		switch job.Protocol {
		case "ssh", "rdp", "vnc", "web", "mysql":
		default:
			return fmt.Errorf("job has unsupported protocol")
		}
		switch job.Mode {
		case "direct":
			direct++
			if _, ok := supported[job.Protocol]; !ok {
				return fmt.Errorf("job direct protocol is unsupported")
			}
		case "browser":
			browser++
			if job.Protocol != "rdp" && job.Protocol != "vnc" && job.Protocol != "web" && job.Protocol != "mysql" {
				return fmt.Errorf("job browser protocol is unsupported")
			}
		default:
			return fmt.Errorf("job has unsupported execution mode")
		}
		if _, ok := jobIDs[job.ID]; ok {
			return fmt.Errorf("duplicate job ID")
		}
		if _, ok := assetIDs[job.AssetID]; ok {
			return fmt.Errorf("duplicate asset binding")
		}
		if _, ok := accountIDs[job.AccountID]; ok {
			return fmt.Errorf("duplicate account binding")
		}
		jobIDs[job.ID], assetIDs[job.AssetID], accountIDs[job.AccountID] = struct{}{}, struct{}{}, struct{}{}
	}
	if direct > capabilities.DirectCapacity {
		return fmt.Errorf("job count exceeds agent direct capacity")
	}
	if browser > capabilities.BrowserCapacity {
		return fmt.Errorf("job count exceeds agent browser capacity")
	}
	return nil
}
