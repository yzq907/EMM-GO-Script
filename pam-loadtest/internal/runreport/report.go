package runreport

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/session"
)

const SchemaVersion = 3

type Measurements struct {
	ConnectLatencyP50Millis float64   `json:"connect_latency_p50_ms"`
	ConnectLatencyP95Millis float64   `json:"connect_latency_p95_ms"`
	ConnectLatencyP99Millis float64   `json:"connect_latency_p99_ms"`
	PrepareP50Millis        float64   `json:"prepare_p50_ms"`
	PrepareP95Millis        float64   `json:"prepare_p95_ms"`
	PrepareP99Millis        float64   `json:"prepare_p99_ms"`
	EditorReadyP50Millis    float64   `json:"editor_ready_p50_ms"`
	EditorReadyP95Millis    float64   `json:"editor_ready_p95_ms"`
	EditorReadyP99Millis    float64   `json:"editor_ready_p99_ms"`
	SentBytes               int64     `json:"sent_bytes"`
	ReceivedBytes           int64     `json:"received_bytes"`
	ActivityEvents          int64     `json:"activity_events"`
	ActiveSessions          int       `json:"active_sessions"`
	BidirectionalSessions   int       `json:"bidirectional_sessions"`
	LastActivitySessions    int       `json:"last_activity_sessions"`
	LastActivity            time.Time `json:"last_activity,omitempty"`
	ConnectLatencySamples   []float64 `json:"connect_latency_samples_ms,omitempty"`
	PrepareSamples          []float64 `json:"prepare_samples_ms,omitempty"`
	EditorReadySamples      []float64 `json:"editor_ready_samples_ms,omitempty"`
}

type Counts struct {
	Planned               int `json:"planned"`
	Used                  int `json:"used"`
	Duplicates            int `json:"duplicates"`
	Unused                int `json:"unused"`
	Started               int `json:"started"`
	StartFailures         int `json:"start_failures"`
	RuntimeFailures       int `json:"runtime_failures"`
	Maintained            int `json:"maintained"`
	ConnectRetryAttempts  int `json:"connect_retry_attempts"`
	ConnectRetrySuccesses int `json:"connect_retry_successes"`
	ConnectRetryExhausted int `json:"connect_retry_exhausted"`
}

type Report struct {
	Version           int                                   `json:"version"`
	BuildVersion      string                                `json:"build_version"`
	RunID             string                                `json:"run_id"`
	Status            string                                `json:"status"`
	Totals            Counts                                `json:"totals"`
	Protocols         map[config.Protocol]Counts            `json:"protocols"`
	Modes             map[config.ExecutionMode]Counts       `json:"modes"`
	Dimensions        map[string]Counts                     `json:"dimensions"`
	Evidence          Measurements                          `json:"evidence"`
	ProtocolEvidence  map[config.Protocol]Measurements      `json:"protocol_evidence"`
	ModeEvidence      map[config.ExecutionMode]Measurements `json:"mode_evidence"`
	DimensionEvidence map[string]Measurements               `json:"dimension_evidence"`
	FailureReasons    map[string]int                        `json:"failure_reasons,omitempty"`
	Agents            map[string]Report                     `json:"agents,omitempty"`
}

type Tracker struct {
	mu                sync.Mutex
	runID             string
	buildVersion      string
	totals            Counts
	protocols         map[config.Protocol]Counts
	modes             map[config.ExecutionMode]Counts
	dimensions        map[string]Counts
	evidence          Measurements
	protocolEvidence  map[config.Protocol]Measurements
	modeEvidence      map[config.ExecutionMode]Measurements
	dimensionEvidence map[string]Measurements
	failureReasons    map[string]int
	used              map[string]struct{}
	usedByProto       map[config.Protocol]map[string]struct{}
}

func NewTracker(runID string, jobs []config.Job) (*Tracker, error) {
	return NewTrackerWithBuildVersion(runID, "dev", jobs)
}

func NewTrackerWithBuildVersion(runID, buildVersion string, jobs []config.Job) (*Tracker, error) {
	if buildVersion == "" {
		return nil, fmt.Errorf("report build version is required")
	}
	tracker := &Tracker{
		runID: runID, buildVersion: buildVersion,
		protocols: make(map[config.Protocol]Counts), modes: make(map[config.ExecutionMode]Counts), dimensions: make(map[string]Counts),
		protocolEvidence: make(map[config.Protocol]Measurements), modeEvidence: make(map[config.ExecutionMode]Measurements), dimensionEvidence: make(map[string]Measurements),
		failureReasons: make(map[string]int),
		used:           make(map[string]struct{}), usedByProto: make(map[config.Protocol]map[string]struct{}),
	}
	planned := make(map[string]struct{}, len(jobs))
	for _, job := range jobs {
		if job.AssetID == "" || job.AccountID == "" {
			return nil, fmt.Errorf("job %d is missing an asset binding", job.ID)
		}
		if job.Mode != config.Direct && job.Mode != config.Browser {
			return nil, fmt.Errorf("job %d is missing an execution mode", job.ID)
		}
		if _, exists := planned[job.AssetID]; exists {
			return nil, fmt.Errorf("planned jobs contain a duplicate asset")
		}
		planned[job.AssetID] = struct{}{}
		tracker.totals.Planned++
		counts := tracker.protocols[job.Protocol]
		counts.Planned++
		tracker.protocols[job.Protocol] = counts
		modeCounts := tracker.modes[job.Mode]
		modeCounts.Planned++
		tracker.modes[job.Mode] = modeCounts
		key := dimensionKey(job.Protocol, job.Mode)
		dimensionCounts := tracker.dimensions[key]
		dimensionCounts.Planned++
		tracker.dimensions[key] = dimensionCounts
		if tracker.usedByProto[job.Protocol] == nil {
			tracker.usedByProto[job.Protocol] = make(map[string]struct{})
		}
		if _, exists := tracker.protocolEvidence[job.Protocol]; !exists {
			tracker.protocolEvidence[job.Protocol] = Measurements{}
		}
		if _, exists := tracker.modeEvidence[job.Mode]; !exists {
			tracker.modeEvidence[job.Mode] = Measurements{}
		}
		if _, exists := tracker.dimensionEvidence[key]; !exists {
			tracker.dimensionEvidence[key] = Measurements{}
		}
	}
	return tracker, nil
}

func (t *Tracker) Attempt(job config.Job) {
	t.mu.Lock()
	defer t.mu.Unlock()
	counts := t.protocols[job.Protocol]
	modeCounts := t.modes[job.Mode]
	key := dimensionKey(job.Protocol, job.Mode)
	dimensionCounts := t.dimensions[key]
	if _, exists := t.used[job.AssetID]; exists {
		t.totals.Duplicates++
		counts.Duplicates++
		modeCounts.Duplicates++
		dimensionCounts.Duplicates++
	} else {
		t.used[job.AssetID] = struct{}{}
		t.totals.Used++
		counts.Used++
		modeCounts.Used++
		dimensionCounts.Used++
	}
	t.usedByProto[job.Protocol][job.AssetID] = struct{}{}
	t.protocols[job.Protocol] = counts
	t.modes[job.Mode] = modeCounts
	t.dimensions[key] = dimensionCounts
}

func (t *Tracker) Started(job config.Job) { t.increment(job, func(c *Counts) { c.Started++ }) }
func (t *Tracker) StartFailed(job config.Job, failure ...error) {
	t.increment(job, func(c *Counts) { c.StartFailures++ })
	t.recordFailure("start", firstError(failure))
}
func (t *Tracker) RuntimeFailed(job config.Job, failure ...error) {
	t.increment(job, func(c *Counts) { c.RuntimeFailures++ })
	t.recordFailure("runtime", firstError(failure))
}
func (t *Tracker) Maintained(job config.Job) { t.increment(job, func(c *Counts) { c.Maintained++ }) }
func (t *Tracker) ConnectRetry(job config.Job) {
	t.increment(job, func(c *Counts) { c.ConnectRetryAttempts++ })
}
func (t *Tracker) ConnectRetrySucceeded(job config.Job) {
	t.increment(job, func(c *Counts) { c.ConnectRetrySuccesses++ })
}
func (t *Tracker) ConnectRetryExhausted(job config.Job) {
	t.increment(job, func(c *Counts) { c.ConnectRetryExhausted++ })
}

func (t *Tracker) Record(job config.Job, observation session.Observation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	addObservation(&t.evidence, observation)
	protocolEvidence := t.protocolEvidence[job.Protocol]
	addObservation(&protocolEvidence, observation)
	t.protocolEvidence[job.Protocol] = protocolEvidence
	modeEvidence := t.modeEvidence[job.Mode]
	addObservation(&modeEvidence, observation)
	t.modeEvidence[job.Mode] = modeEvidence
	key := dimensionKey(job.Protocol, job.Mode)
	dimensionEvidence := t.dimensionEvidence[key]
	addObservation(&dimensionEvidence, observation)
	t.dimensionEvidence[key] = dimensionEvidence
}

func (t *Tracker) increment(job config.Job, update func(*Counts)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	update(&t.totals)
	counts := t.protocols[job.Protocol]
	update(&counts)
	t.protocols[job.Protocol] = counts
	modeCounts := t.modes[job.Mode]
	update(&modeCounts)
	t.modes[job.Mode] = modeCounts
	key := dimensionKey(job.Protocol, job.Mode)
	dimensionCounts := t.dimensions[key]
	update(&dimensionCounts)
	t.dimensions[key] = dimensionCounts
}

func (t *Tracker) Snapshot(status string) Report {
	t.mu.Lock()
	defer t.mu.Unlock()
	totals := t.totals
	totals.Maintained = totals.Started - totals.RuntimeFailures
	totals.Unused = totals.Planned - totals.Used
	protocols := make(map[config.Protocol]Counts, len(t.protocols))
	for protocol, counts := range t.protocols {
		counts.Maintained = counts.Started - counts.RuntimeFailures
		counts.Unused = counts.Planned - counts.Used
		protocols[protocol] = counts
	}
	modes := make(map[config.ExecutionMode]Counts, len(t.modes))
	for mode, counts := range t.modes {
		counts.Maintained = counts.Started - counts.RuntimeFailures
		counts.Unused = counts.Planned - counts.Used
		modes[mode] = counts
	}
	dimensions := make(map[string]Counts, len(t.dimensions))
	for key, counts := range t.dimensions {
		counts.Maintained = counts.Started - counts.RuntimeFailures
		counts.Unused = counts.Planned - counts.Used
		dimensions[key] = counts
	}
	return Report{
		Version: SchemaVersion, BuildVersion: t.buildVersion, RunID: t.runID, Status: status, Totals: totals, Protocols: protocols, Modes: modes, Dimensions: dimensions,
		Evidence:          finalizedMeasurements(t.evidence),
		ProtocolEvidence:  finalizedMeasurementMap(t.protocolEvidence),
		ModeEvidence:      finalizedMeasurementMap(t.modeEvidence),
		DimensionEvidence: finalizedMeasurementMap(t.dimensionEvidence),
		FailureReasons:    cloneFailureReasons(t.failureReasons),
	}
}

func Aggregate(runID string, expected map[string][]config.Job, reports map[string]Report) (Report, error) {
	buildVersion := ""
	for _, report := range reports {
		if report.BuildVersion != "" {
			buildVersion = report.BuildVersion
			break
		}
	}
	return AggregateForBuild(runID, buildVersion, expected, reports)
}

func AggregateTerminalForBuild(runID, buildVersion string, expected map[string][]config.Job, reports map[string]Report, status string) (Report, error) {
	if status != "failed" && status != "cancelled" {
		return Report{}, fmt.Errorf("terminal aggregate status is invalid")
	}
	if len(reports) != len(expected) {
		return Report{}, fmt.Errorf("agent report count mismatch")
	}
	result := Report{
		Version: SchemaVersion, BuildVersion: buildVersion, RunID: runID, Status: status,
		Protocols: make(map[config.Protocol]Counts), Modes: make(map[config.ExecutionMode]Counts), Dimensions: make(map[string]Counts),
		ProtocolEvidence: make(map[config.Protocol]Measurements), ModeEvidence: make(map[config.ExecutionMode]Measurements), DimensionEvidence: make(map[string]Measurements), Agents: make(map[string]Report),
		FailureReasons: make(map[string]int),
	}
	globalAssets := make(map[string]struct{})
	for agent, jobs := range expected {
		report, ok := reports[agent]
		if !ok {
			return Report{}, fmt.Errorf("agent report is missing")
		}
		if report.Version != SchemaVersion || report.BuildVersion != buildVersion || report.RunID != runID || (report.Status != "completed" && report.Status != "failed" && report.Status != "cancelled") {
			return Report{}, fmt.Errorf("agent report terminal state mismatch")
		}
		if _, err := validateReportDimensions(report, jobs, globalAssets, false); err != nil {
			return Report{}, err
		}
		for protocol, counts := range report.Protocols {
			merged := result.Protocols[protocol]
			addCounts(&merged, counts)
			result.Protocols[protocol] = merged
		}
		for mode, counts := range report.Modes {
			merged := result.Modes[mode]
			addCounts(&merged, counts)
			result.Modes[mode] = merged
		}
		for key, counts := range report.Dimensions {
			merged := result.Dimensions[key]
			addCounts(&merged, counts)
			result.Dimensions[key] = merged
		}
		copy := report
		copy.Agents = nil
		result.Agents[agent] = copy
		addCounts(&result.Totals, report.Totals)
		mergeMeasurements(&result.Evidence, report.Evidence)
		mergeMeasurementMap(result.ProtocolEvidence, report.ProtocolEvidence)
		mergeMeasurementMap(result.ModeEvidence, report.ModeEvidence)
		mergeMeasurementMap(result.DimensionEvidence, report.DimensionEvidence)
		mergeFailureReasons(result.FailureReasons, report.FailureReasons)
	}
	result.Evidence = finalizedMeasurements(result.Evidence)
	result.ProtocolEvidence = finalizedMeasurementMap(result.ProtocolEvidence)
	result.ModeEvidence = finalizedMeasurementMap(result.ModeEvidence)
	result.DimensionEvidence = finalizedMeasurementMap(result.DimensionEvidence)
	return result, nil
}

func AggregateForBuild(runID, buildVersion string, expected map[string][]config.Job, reports map[string]Report) (Report, error) {
	return aggregateForBuild(runID, buildVersion, expected, reports, true)
}

// AggregateConnectionOnlyForBuild verifies ownership and terminal session
// counts for read-only connection tests. Unlike active workload validation it
// intentionally does not require application activity or bidirectional data.
func AggregateConnectionOnlyForBuild(runID, buildVersion string, expected map[string][]config.Job, reports map[string]Report) (Report, error) {
	return aggregateForBuild(runID, buildVersion, expected, reports, false)
}

func aggregateForBuild(runID, buildVersion string, expected map[string][]config.Job, reports map[string]Report, requireActivityEvidence bool) (Report, error) {
	if len(reports) != len(expected) {
		return Report{}, fmt.Errorf("agent report count mismatch")
	}
	globalAssets := make(map[string]struct{})
	result := Report{
		Version: SchemaVersion, BuildVersion: buildVersion, RunID: runID, Status: "completed", Protocols: make(map[config.Protocol]Counts), Modes: make(map[config.ExecutionMode]Counts), Dimensions: make(map[string]Counts),
		ProtocolEvidence: make(map[config.Protocol]Measurements), ModeEvidence: make(map[config.ExecutionMode]Measurements), DimensionEvidence: make(map[string]Measurements), Agents: make(map[string]Report),
		FailureReasons: make(map[string]int),
	}
	for agent, jobs := range expected {
		report, ok := reports[agent]
		if !ok {
			return Report{}, fmt.Errorf("agent report is missing")
		}
		if report.Version != SchemaVersion || report.BuildVersion != buildVersion || report.Status != "completed" || report.RunID != runID {
			return Report{}, fmt.Errorf("agent report terminal state mismatch")
		}
		if _, err := validateReportDimensions(report, jobs, globalAssets, requireActivityEvidence); err != nil {
			return Report{}, err
		}
		for protocol, counts := range report.Protocols {
			merged := result.Protocols[protocol]
			addCounts(&merged, counts)
			result.Protocols[protocol] = merged
		}
		for mode, counts := range report.Modes {
			merged := result.Modes[mode]
			addCounts(&merged, counts)
			result.Modes[mode] = merged
		}
		for key, counts := range report.Dimensions {
			merged := result.Dimensions[key]
			addCounts(&merged, counts)
			result.Dimensions[key] = merged
		}
		copy := report
		copy.Agents = nil
		result.Agents[agent] = copy
		addCounts(&result.Totals, report.Totals)
		mergeMeasurements(&result.Evidence, report.Evidence)
		mergeMeasurementMap(result.ProtocolEvidence, report.ProtocolEvidence)
		mergeMeasurementMap(result.ModeEvidence, report.ModeEvidence)
		mergeMeasurementMap(result.DimensionEvidence, report.DimensionEvidence)
		mergeFailureReasons(result.FailureReasons, report.FailureReasons)
	}
	if result.Totals.Planned != len(globalAssets) || result.Totals.Duplicates != 0 {
		return Report{}, fmt.Errorf("global report counts are inconsistent")
	}
	result.Evidence = finalizedMeasurements(result.Evidence)
	result.ProtocolEvidence = finalizedMeasurementMap(result.ProtocolEvidence)
	result.ModeEvidence = finalizedMeasurementMap(result.ModeEvidence)
	result.DimensionEvidence = finalizedMeasurementMap(result.DimensionEvidence)
	return result, nil
}

func firstError(values []error) error {
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

func (t *Tracker) recordFailure(phase string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failureReasons[phase+"/"+failureCategory(err)]++
}

func failureCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "no_connect"):
		return "pam_no_connect"
	case strings.Contains(message, "pam session connect timeout"):
		return "pam_connect_timeout"
	case strings.Contains(message, "inbound traffic inactive"):
		return "inbound_inactive"
	case strings.Contains(message, "guacamole read failed"):
		return "guacamole_read"
	case strings.Contains(message, "guacamole activity failed"):
		return "guacamole_activity"
	case strings.Contains(message, "guacamole keepalive failed"):
		return "guacamole_keepalive"
	case strings.Contains(message, "deadline exceeded"), strings.Contains(message, "timeout"), strings.Contains(message, "timed out"):
		return "timeout"
	case strings.Contains(message, "connection refused"):
		return "connection_refused"
	case strings.Contains(message, "status 401"), strings.Contains(message, "status 403"), strings.Contains(message, "unauthorized"), strings.Contains(message, "forbidden"), strings.Contains(message, "license"):
		return "authorization"
	case strings.Contains(message, "status 5"), strings.Contains(message, "http 5"):
		return "pam_http_5xx"
	case strings.Contains(message, "websocket"), strings.Contains(message, "unexpected eof"), strings.Contains(message, "connection reset"), strings.Contains(message, "broken pipe"):
		return "transport_closed"
	case strings.Contains(message, "context canceled"):
		return "cancelled"
	default:
		return "other"
	}
}

func cloneFailureReasons(source map[string]int) map[string]int {
	result := make(map[string]int, len(source))
	for reason, count := range source {
		result[reason] = count
	}
	return result
}

func mergeFailureReasons(target, source map[string]int) {
	for reason, count := range source {
		target[reason] += count
	}
}

type reportExpectation struct {
	plannedByProtocol   map[config.Protocol]int
	plannedByMode       map[config.ExecutionMode]int
	plannedByDimension  map[string]int
	protocolByDimension map[string]config.Protocol
	modeByDimension     map[string]config.ExecutionMode
}

func validateReportDimensions(report Report, jobs []config.Job, globalAssets map[string]struct{}, requireSuccessful bool) (reportExpectation, error) {
	expected := reportExpectation{
		plannedByProtocol: make(map[config.Protocol]int), plannedByMode: make(map[config.ExecutionMode]int), plannedByDimension: make(map[string]int),
		protocolByDimension: make(map[string]config.Protocol), modeByDimension: make(map[string]config.ExecutionMode),
	}
	for _, job := range jobs {
		if _, exists := globalAssets[job.AssetID]; exists {
			return reportExpectation{}, fmt.Errorf("global asset assignment contains a duplicate")
		}
		globalAssets[job.AssetID] = struct{}{}
		expected.plannedByProtocol[job.Protocol]++
		expected.plannedByMode[job.Mode]++
		key := dimensionKey(job.Protocol, job.Mode)
		expected.plannedByDimension[key]++
		expected.protocolByDimension[key] = job.Protocol
		expected.modeByDimension[key] = job.Mode
	}
	if report.Totals.Planned != len(jobs) || !validCounts(report.Totals) {
		return reportExpectation{}, fmt.Errorf("agent report counts are invalid")
	}
	if requireSuccessful && (report.Totals.Used != report.Totals.Planned || report.Totals.Duplicates != 0 || report.Totals.Unused != 0 || report.Totals.StartFailures != 0 || report.Totals.RuntimeFailures != 0 || report.Totals.Started != report.Totals.Planned || report.Totals.Maintained != report.Totals.Started) {
		return reportExpectation{}, fmt.Errorf("agent report counts are inconsistent")
	}

	protocolTotal := Counts{}
	for protocol, planned := range expected.plannedByProtocol {
		counts, ok := report.Protocols[protocol]
		if !ok || counts.Planned != planned || !validCounts(counts) {
			return reportExpectation{}, fmt.Errorf("agent protocol report counts are inconsistent")
		}
		addCounts(&protocolTotal, counts)
	}
	for protocol := range report.Protocols {
		if _, ok := expected.plannedByProtocol[protocol]; !ok {
			return reportExpectation{}, fmt.Errorf("agent report contains an unexpected protocol")
		}
	}
	if protocolTotal != report.Totals {
		return reportExpectation{}, fmt.Errorf("agent protocol totals do not match report totals")
	}

	modeTotal := Counts{}
	for mode, planned := range expected.plannedByMode {
		counts, ok := report.Modes[mode]
		if !ok || counts.Planned != planned || !validCounts(counts) {
			return reportExpectation{}, fmt.Errorf("agent mode report counts are inconsistent")
		}
		addCounts(&modeTotal, counts)
	}
	for mode := range report.Modes {
		if _, ok := expected.plannedByMode[mode]; !ok {
			return reportExpectation{}, fmt.Errorf("agent report contains an unexpected mode")
		}
	}
	if modeTotal != report.Totals {
		return reportExpectation{}, fmt.Errorf("agent mode totals do not match report totals")
	}

	dimensionTotal := Counts{}
	for key, planned := range expected.plannedByDimension {
		counts, ok := report.Dimensions[key]
		if !ok || counts.Planned != planned || !validCounts(counts) {
			return reportExpectation{}, fmt.Errorf("agent dimension report counts are inconsistent")
		}
		addCounts(&dimensionTotal, counts)
	}
	for key := range report.Dimensions {
		if _, ok := expected.plannedByDimension[key]; !ok {
			return reportExpectation{}, fmt.Errorf("agent report contains an unexpected dimension")
		}
	}
	if dimensionTotal != report.Totals {
		return reportExpectation{}, fmt.Errorf("agent dimension totals do not match report totals")
	}
	if err := validateEvidence(report, expected.plannedByProtocol, expected.plannedByMode, expected.plannedByDimension, expected.protocolByDimension, expected.modeByDimension, requireSuccessful); err != nil {
		return reportExpectation{}, err
	}
	return expected, nil
}

func addObservation(target *Measurements, observation session.Observation) {
	if observation.ConnectLatency > 0 {
		target.ConnectLatencySamples = append(target.ConnectLatencySamples, float64(observation.ConnectLatency)/float64(time.Millisecond))
	}
	if observation.PrepareLatency > 0 {
		target.PrepareSamples = append(target.PrepareSamples, float64(observation.PrepareLatency)/float64(time.Millisecond))
	}
	if observation.EditorReadyLatency > 0 {
		target.EditorReadySamples = append(target.EditorReadySamples, float64(observation.EditorReadyLatency)/float64(time.Millisecond))
	}
	target.SentBytes += observation.SentBytes
	target.ReceivedBytes += observation.ReceivedBytes
	target.ActivityEvents += observation.ActivityEvents
	if observation.ActivityEvents > 0 {
		target.ActiveSessions++
	}
	if observation.SentBytes > 0 && observation.ReceivedBytes > 0 {
		target.BidirectionalSessions++
	}
	if !observation.LastActivity.IsZero() {
		target.LastActivitySessions++
	}
	if observation.LastActivity.After(target.LastActivity) {
		target.LastActivity = observation.LastActivity
	}
}

func mergeMeasurements(target *Measurements, value Measurements) {
	target.SentBytes += value.SentBytes
	target.ReceivedBytes += value.ReceivedBytes
	target.ActivityEvents += value.ActivityEvents
	target.ActiveSessions += value.ActiveSessions
	target.BidirectionalSessions += value.BidirectionalSessions
	target.LastActivitySessions += value.LastActivitySessions
	if value.LastActivity.After(target.LastActivity) {
		target.LastActivity = value.LastActivity
	}
	target.ConnectLatencySamples = append(target.ConnectLatencySamples, value.ConnectLatencySamples...)
	target.PrepareSamples = append(target.PrepareSamples, value.PrepareSamples...)
	target.EditorReadySamples = append(target.EditorReadySamples, value.EditorReadySamples...)
}

func mergeMeasurementMap[K comparable](target map[K]Measurements, values map[K]Measurements) {
	for key, value := range values {
		merged := target[key]
		mergeMeasurements(&merged, value)
		target[key] = merged
	}
}

func finalizedMeasurementMap[K comparable](source map[K]Measurements) map[K]Measurements {
	result := make(map[K]Measurements, len(source))
	for key, value := range source {
		result[key] = finalizedMeasurements(value)
	}
	return result
}

func finalizedMeasurements(value Measurements) Measurements {
	value.ConnectLatencySamples = append([]float64(nil), value.ConnectLatencySamples...)
	value.PrepareSamples = append([]float64(nil), value.PrepareSamples...)
	value.EditorReadySamples = append([]float64(nil), value.EditorReadySamples...)
	sort.Float64s(value.ConnectLatencySamples)
	sort.Float64s(value.PrepareSamples)
	sort.Float64s(value.EditorReadySamples)
	value.ConnectLatencyP50Millis = quantile(value.ConnectLatencySamples, .50)
	value.ConnectLatencyP95Millis = quantile(value.ConnectLatencySamples, .95)
	value.ConnectLatencyP99Millis = quantile(value.ConnectLatencySamples, .99)
	value.PrepareP50Millis = quantile(value.PrepareSamples, .50)
	value.PrepareP95Millis = quantile(value.PrepareSamples, .95)
	value.PrepareP99Millis = quantile(value.PrepareSamples, .99)
	value.EditorReadyP50Millis = quantile(value.EditorReadySamples, .50)
	value.EditorReadyP95Millis = quantile(value.EditorReadySamples, .95)
	value.EditorReadyP99Millis = quantile(value.EditorReadySamples, .99)
	return value
}

func quantile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(values)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

func validateEvidence(report Report, plannedByProtocol map[config.Protocol]int, plannedByMode map[config.ExecutionMode]int, plannedByDimension map[string]int, protocolByDimension map[string]config.Protocol, modeByDimension map[string]config.ExecutionMode, requireMaintained bool) error {
	if len(report.ProtocolEvidence) != len(plannedByProtocol) || len(report.ModeEvidence) != len(plannedByMode) || len(report.DimensionEvidence) != len(plannedByDimension) {
		return fmt.Errorf("agent evidence contains missing or unexpected dimensions")
	}
	wantTotal := Measurements{}
	wantProtocols := make(map[config.Protocol]Measurements, len(plannedByProtocol))
	wantModes := make(map[config.ExecutionMode]Measurements, len(plannedByMode))
	for key := range plannedByDimension {
		value, ok := report.DimensionEvidence[key]
		if !ok || !validMeasurements(value) {
			return fmt.Errorf("agent dimension evidence is invalid")
		}
		counts := report.Dimensions[key]
		if requireMaintained && (len(value.ConnectLatencySamples) != counts.Maintained || value.ActiveSessions != counts.Maintained || value.LastActivitySessions != counts.Maintained || value.ActivityEvents < int64(counts.Maintained)) {
			return fmt.Errorf("agent dimension evidence does not prove maintained sessions")
		}
		if requireMaintained && modeByDimension[key] == config.Direct && value.BidirectionalSessions != counts.Maintained {
			return fmt.Errorf("agent direct evidence is not bidirectional")
		}
		mergeMeasurements(&wantTotal, value)
		protocol := protocolByDimension[key]
		protocolValue := wantProtocols[protocol]
		mergeMeasurements(&protocolValue, value)
		wantProtocols[protocol] = protocolValue
		mode := modeByDimension[key]
		modeValue := wantModes[mode]
		mergeMeasurements(&modeValue, value)
		wantModes[mode] = modeValue
	}
	if !equalMeasurements(report.Evidence, finalizedMeasurements(wantTotal)) {
		return fmt.Errorf("agent total evidence is inconsistent")
	}
	for protocol := range plannedByProtocol {
		if !equalMeasurements(report.ProtocolEvidence[protocol], finalizedMeasurements(wantProtocols[protocol])) {
			return fmt.Errorf("agent protocol evidence is inconsistent")
		}
	}
	for mode := range plannedByMode {
		if !equalMeasurements(report.ModeEvidence[mode], finalizedMeasurements(wantModes[mode])) {
			return fmt.Errorf("agent mode evidence is inconsistent")
		}
	}
	return nil
}

func validMeasurements(value Measurements) bool {
	if value.SentBytes < 0 || value.ReceivedBytes < 0 || value.ActivityEvents < 0 || value.ActiveSessions < 0 || value.BidirectionalSessions < 0 || value.LastActivitySessions < 0 || value.LastActivity.After(time.Now().Add(5*time.Minute)) || math.IsNaN(value.ConnectLatencyP50Millis) || math.IsNaN(value.ConnectLatencyP95Millis) || math.IsNaN(value.ConnectLatencyP99Millis) || math.IsNaN(value.PrepareP50Millis) || math.IsNaN(value.PrepareP95Millis) || math.IsNaN(value.PrepareP99Millis) || math.IsNaN(value.EditorReadyP50Millis) || math.IsNaN(value.EditorReadyP95Millis) || math.IsNaN(value.EditorReadyP99Millis) {
		return false
	}
	for _, sample := range value.ConnectLatencySamples {
		if sample <= 0 || math.IsNaN(sample) || math.IsInf(sample, 0) {
			return false
		}
	}
	for _, sample := range append(append([]float64(nil), value.PrepareSamples...), value.EditorReadySamples...) {
		if sample <= 0 || math.IsNaN(sample) || math.IsInf(sample, 0) {
			return false
		}
	}
	return value.ConnectLatencyP50Millis <= value.ConnectLatencyP95Millis && value.ConnectLatencyP95Millis <= value.ConnectLatencyP99Millis && value.PrepareP50Millis <= value.PrepareP95Millis && value.PrepareP95Millis <= value.PrepareP99Millis && value.EditorReadyP50Millis <= value.EditorReadyP95Millis && value.EditorReadyP95Millis <= value.EditorReadyP99Millis
}

func equalMeasurements(left, right Measurements) bool {
	left = finalizedMeasurements(left)
	right = finalizedMeasurements(right)
	if left.ConnectLatencyP50Millis != right.ConnectLatencyP50Millis || left.ConnectLatencyP95Millis != right.ConnectLatencyP95Millis || left.ConnectLatencyP99Millis != right.ConnectLatencyP99Millis || left.PrepareP50Millis != right.PrepareP50Millis || left.PrepareP95Millis != right.PrepareP95Millis || left.PrepareP99Millis != right.PrepareP99Millis || left.EditorReadyP50Millis != right.EditorReadyP50Millis || left.EditorReadyP95Millis != right.EditorReadyP95Millis || left.EditorReadyP99Millis != right.EditorReadyP99Millis || left.SentBytes != right.SentBytes || left.ReceivedBytes != right.ReceivedBytes || left.ActivityEvents != right.ActivityEvents || left.ActiveSessions != right.ActiveSessions || left.BidirectionalSessions != right.BidirectionalSessions || left.LastActivitySessions != right.LastActivitySessions || !left.LastActivity.Equal(right.LastActivity) || len(left.ConnectLatencySamples) != len(right.ConnectLatencySamples) || len(left.PrepareSamples) != len(right.PrepareSamples) || len(left.EditorReadySamples) != len(right.EditorReadySamples) {
		return false
	}
	for index := range left.ConnectLatencySamples {
		if left.ConnectLatencySamples[index] != right.ConnectLatencySamples[index] {
			return false
		}
	}
	for index := range left.PrepareSamples {
		if left.PrepareSamples[index] != right.PrepareSamples[index] {
			return false
		}
	}
	for index := range left.EditorReadySamples {
		if left.EditorReadySamples[index] != right.EditorReadySamples[index] {
			return false
		}
	}
	return true
}

func validCounts(counts Counts) bool {
	return counts.Planned >= 0 && counts.Used >= 0 && counts.Used <= counts.Planned &&
		counts.Unused >= 0 && counts.Duplicates >= 0 && counts.Started >= 0 &&
		counts.StartFailures >= 0 && counts.Started+counts.StartFailures == counts.Used &&
		counts.RuntimeFailures >= 0 && counts.RuntimeFailures <= counts.Started &&
		counts.Maintained >= 0 && counts.Maintained == counts.Started-counts.RuntimeFailures &&
		counts.ConnectRetryAttempts >= 0 && counts.ConnectRetrySuccesses >= 0 && counts.ConnectRetryExhausted >= 0 &&
		counts.ConnectRetrySuccesses <= counts.ConnectRetryAttempts && counts.ConnectRetryExhausted <= counts.ConnectRetryAttempts
}

func addCounts(target *Counts, value Counts) {
	target.Planned += value.Planned
	target.Used += value.Used
	target.Duplicates += value.Duplicates
	target.Unused += value.Unused
	target.Started += value.Started
	target.StartFailures += value.StartFailures
	target.RuntimeFailures += value.RuntimeFailures
	target.Maintained += value.Maintained
	target.ConnectRetryAttempts += value.ConnectRetryAttempts
	target.ConnectRetrySuccesses += value.ConnectRetrySuccesses
	target.ConnectRetryExhausted += value.ConnectRetryExhausted
}

func dimensionKey(protocol config.Protocol, mode config.ExecutionMode) string {
	return string(protocol) + "/" + string(mode)
}
