package runreport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/session"
)

func TestTrackerClassifiesFailureReasonsWithoutLeakingErrorDetails(t *testing.T) {
	jobs := boundJobs()[:2]
	tracker, err := NewTracker("classified", jobs)
	if err != nil {
		t.Fatal(err)
	}
	tracker.Attempt(jobs[0])
	tracker.StartFailed(jobs[0], errors.New("PAM no_connect for secret-asset-id"))
	tracker.Attempt(jobs[1])
	tracker.Started(jobs[1])
	tracker.RuntimeFailed(jobs[1], errors.New("websocket inbound traffic inactive for 15s: secret-session-id"))

	report := tracker.Snapshot("failed")
	if report.FailureReasons["start/pam_no_connect"] != 1 || report.FailureReasons["runtime/inbound_inactive"] != 1 {
		t.Fatalf("failure reasons=%+v", report.FailureReasons)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-asset-id", "secret-session-id", "no_connect for"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("failure report leaked detail %q", secret)
		}
	}
}

func TestAggregateTerminalMergesFailureReasons(t *testing.T) {
	jobs := boundJobs()[:2]
	expected := map[string][]config.Job{"agent-a": {jobs[0]}, "agent-b": {jobs[1]}}
	reports := make(map[string]Report)
	for agent, assigned := range expected {
		tracker, err := NewTrackerWithBuildVersion("failure-reasons", "build-1", assigned)
		if err != nil {
			t.Fatal(err)
		}
		tracker.Attempt(assigned[0])
		tracker.Started(assigned[0])
		tracker.RuntimeFailed(assigned[0], errors.New("context deadline exceeded"))
		reports[agent] = tracker.Snapshot("failed")
	}

	report, err := AggregateTerminalForBuild("failure-reasons", "build-1", expected, reports, "failed")
	if err != nil {
		t.Fatal(err)
	}
	if report.FailureReasons["runtime/timeout"] != 2 {
		t.Fatalf("failure reasons=%+v", report.FailureReasons)
	}
}

func TestFailureCategoryDistinguishesPAMConnectTimeout(t *testing.T) {
	got := failureCategory(errors.New("PAM session connect timeout: context deadline exceeded"))
	if got != "pam_connect_timeout" {
		t.Fatalf("category=%q", got)
	}
}

func TestTrackerCountsRetriesWithoutDuplicateAssetUse(t *testing.T) {
	job := boundJobs()[0]
	tracker, err := NewTracker("retries", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	tracker.Attempt(job)
	tracker.ConnectRetry(job)
	tracker.ConnectRetry(job)
	tracker.ConnectRetrySucceeded(job)
	tracker.Started(job)
	tracker.Maintained(job)
	report := tracker.Snapshot("completed")
	if report.Totals.Used != 1 || report.Totals.Duplicates != 0 || report.Totals.ConnectRetryAttempts != 2 || report.Totals.ConnectRetrySuccesses != 1 || report.Totals.ConnectRetryExhausted != 0 {
		t.Fatalf("totals=%+v", report.Totals)
	}
}

func TestFailureCategoryClassifiesGuacamoleRuntimeErrors(t *testing.T) {
	tests := map[string]string{
		"guacamole read failed: protected-detail":      "guacamole_read",
		"guacamole activity failed: protected-detail":  "guacamole_activity",
		"guacamole keepalive failed: protected-detail": "guacamole_keepalive",
	}
	for message, want := range tests {
		if got := failureCategory(errors.New(message)); got != want {
			t.Errorf("message=%q category=%q want=%q", message, got, want)
		}
	}
}

func boundJobs() []config.Job {
	return []config.Job{
		{ID: 1, Protocol: config.SSH, Mode: config.Direct, AssetID: "a-1", AccountID: "u-1"},
		{ID: 2, Protocol: config.SSH, Mode: config.Direct, AssetID: "a-2", AccountID: "u-2"},
		{ID: 3, Protocol: config.RDP, Mode: config.Browser, AssetID: "a-3", AccountID: "u-3"},
	}
}

func TestTrackerRecordsTerminalEvidence(t *testing.T) {
	tracker, err := NewTracker("evidence", boundJobs()[:2])
	if err != nil {
		t.Fatal(err)
	}
	for index, job := range boundJobs()[:2] {
		tracker.Attempt(job)
		tracker.Started(job)
		tracker.Maintained(job)
		tracker.Record(job, session.Observation{ConnectLatency: time.Duration(index+1) * 100 * time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 3})
	}
	report := tracker.Snapshot("completed")
	if report.Evidence.SentBytes != 20 || report.Evidence.ReceivedBytes != 40 || report.Evidence.ActivityEvents != 6 {
		t.Fatalf("evidence=%+v", report.Evidence)
	}
	if report.Evidence.ConnectLatencyP50Millis != 100 || report.Evidence.ConnectLatencyP99Millis != 200 {
		t.Fatalf("evidence=%+v", report.Evidence)
	}
	if report.DimensionEvidence["ssh/direct"].ActivityEvents != 6 {
		t.Fatalf("dimensions=%+v", report.DimensionEvidence)
	}
}

func TestMySQLGUIPhaseTimings(t *testing.T) {
	job := config.Job{ID: 4, Protocol: config.MySQL, Mode: config.Browser, AssetID: "mysql-asset", AccountID: "mysql-account"}
	tracker, err := NewTracker("mysql-gui-timing", []config.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	tracker.Attempt(job)
	tracker.Started(job)
	tracker.Maintained(job)
	tracker.Record(job, session.Observation{
		ConnectLatency:     2200 * time.Millisecond,
		PrepareLatency:     7100 * time.Millisecond,
		EditorReadyLatency: 400 * time.Millisecond,
		ActivityEvents:     1,
		LastActivity:       time.Now(),
	})
	report := tracker.Snapshot("completed")
	evidence := report.ProtocolEvidence[config.MySQL]
	if evidence.ConnectLatencyP50Millis != 2200 || evidence.PrepareP50Millis != 7100 || evidence.EditorReadyP50Millis != 400 {
		t.Fatalf("mysql evidence=%+v", evidence)
	}
}

func TestTrackerReportsPlannedUsedDuplicateUnusedAndFailures(t *testing.T) {
	tracker, err := NewTracker("run-1", boundJobs())
	if err != nil {
		t.Fatal(err)
	}
	tracker.Attempt(boundJobs()[0])
	tracker.Started(boundJobs()[0])
	tracker.Attempt(boundJobs()[0])
	tracker.StartFailed(boundJobs()[1])
	tracker.RuntimeFailed(boundJobs()[0])
	report := tracker.Snapshot("failed")
	if report.Totals.Planned != 3 || report.Totals.Used != 1 || report.Totals.Duplicates != 1 || report.Totals.Unused != 2 || report.Totals.Started != 1 || report.Totals.StartFailures != 1 || report.Totals.RuntimeFailures != 1 {
		t.Fatalf("totals=%+v", report.Totals)
	}
	if report.Protocols[config.SSH].Planned != 2 || report.Protocols[config.RDP].Planned != 1 {
		t.Fatalf("protocols=%+v", report.Protocols)
	}
	if report.Modes[config.Direct].Planned != 2 || report.Modes[config.Browser].Planned != 1 {
		t.Fatalf("modes=%+v", report.Modes)
	}
	if report.Dimensions["ssh/direct"].Planned != 2 || report.Dimensions["rdp/browser"].Planned != 1 {
		t.Fatalf("dimensions=%+v", report.Dimensions)
	}
}

func TestNewTrackerRejectsMissingOrDuplicateBindings(t *testing.T) {
	jobs := boundJobs()
	jobs[0].AssetID = ""
	if _, err := NewTracker("run", jobs); err == nil {
		t.Fatal("expected missing binding error")
	}
	jobs = boundJobs()
	jobs[1].AssetID = jobs[0].AssetID
	if _, err := NewTracker("run", jobs); err == nil {
		t.Fatal("expected duplicate binding error")
	}
}

func TestValidateAndAggregateReports(t *testing.T) {
	one, _ := NewTracker("run", boundJobs()[:2])
	for _, job := range boundJobs()[:2] {
		one.Attempt(job)
		one.Started(job)
		one.Record(job, session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
	}
	two, _ := NewTracker("run", boundJobs()[2:])
	two.Attempt(boundJobs()[2])
	two.Started(boundJobs()[2])
	two.Record(boundJobs()[2], session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
	aggregated, err := Aggregate("run", map[string][]config.Job{"agent-a": boundJobs()[:2], "agent-b": boundJobs()[2:]}, map[string]Report{"agent-a": one.Snapshot("completed"), "agent-b": two.Snapshot("completed")})
	if err != nil {
		t.Fatal(err)
	}
	if aggregated.Totals.Planned != 3 || aggregated.Totals.Used != 3 || aggregated.Totals.Duplicates != 0 || aggregated.Protocols[config.SSH].Used != 2 {
		t.Fatalf("report=%+v", aggregated)
	}
	bad := one.Snapshot("completed")
	bad.Totals.Duplicates = 1
	if _, err := Aggregate("run", map[string][]config.Job{"agent-a": boundJobs()[:2]}, map[string]Report{"agent-a": bad}); err == nil {
		t.Fatal("expected duplicate report rejection")
	}
}

func TestSnapshotDerivesMaintainedFromStartedMinusRuntimeFailures(t *testing.T) {
	tracker, err := NewTracker("maintained", boundJobs()[:2])
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range boundJobs()[:2] {
		tracker.Attempt(job)
		tracker.Started(job)
	}
	tracker.RuntimeFailed(boundJobs()[1])
	report := tracker.Snapshot("completed")
	if report.Totals.Maintained != 1 || report.Protocols[config.SSH].Maintained != 1 || report.Dimensions["ssh/direct"].Maintained != 1 {
		t.Fatalf("maintained counts were not derived: %+v", report)
	}
}

func TestAggregateRecomputesQuantilesAndRejectsMissingDimensionEvidence(t *testing.T) {
	one, _ := NewTracker("run", boundJobs()[:1])
	one.Attempt(boundJobs()[0])
	one.Started(boundJobs()[0])
	one.Record(boundJobs()[0], session.Observation{ConnectLatency: 100 * time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 2, LastActivity: time.Now()})
	two, _ := NewTracker("run", boundJobs()[1:2])
	two.Attempt(boundJobs()[1])
	two.Started(boundJobs()[1])
	two.Record(boundJobs()[1], session.Observation{ConnectLatency: 300 * time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 3, LastActivity: time.Now()})
	expected := map[string][]config.Job{"agent-a": boundJobs()[:1], "agent-b": boundJobs()[1:2]}
	reports := map[string]Report{"agent-a": one.Snapshot("completed"), "agent-b": two.Snapshot("completed")}
	aggregated, err := Aggregate("run", expected, reports)
	if err != nil {
		t.Fatal(err)
	}
	if aggregated.Evidence.ConnectLatencyP50Millis != 100 || aggregated.Evidence.ConnectLatencyP99Millis != 300 || aggregated.Evidence.ActivityEvents != 5 {
		t.Fatalf("aggregated evidence=%+v", aggregated.Evidence)
	}
	bad := reports["agent-a"]
	delete(bad.DimensionEvidence, "ssh/direct")
	reports["agent-a"] = bad
	if _, err := Aggregate("run", expected, reports); err == nil {
		t.Fatal("expected missing dimension evidence rejection")
	}
}

func TestReportJSONDoesNotContainAssetOrAccountIDs(t *testing.T) {
	tracker, _ := NewTracker("redacted", boundJobs())
	body, err := json.Marshal(tracker.Snapshot("completed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secretID := range []string{"a-1", "a-2", "a-3", "u-1", "u-2", "u-3"} {
		if strings.Contains(string(body), secretID) {
			t.Fatalf("report leaked runtime ID %q", secretID)
		}
	}
}

func TestAggregateRejectsUnusedAndTerminalFailures(t *testing.T) {
	jobs := boundJobs()[:1]
	unused, _ := NewTracker("run", jobs)
	if _, err := Aggregate("run", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": unused.Snapshot("completed")}); err == nil {
		t.Fatal("expected unused asset rejection")
	}
	failed, _ := NewTracker("run", jobs)
	failed.Attempt(jobs[0])
	failed.Started(jobs[0])
	failed.RuntimeFailed(jobs[0])
	failed.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, ActivityEvents: 1})
	if _, err := Aggregate("run", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": failed.Snapshot("completed")}); err == nil {
		t.Fatal("expected runtime failure rejection")
	}
}

func TestAggregateRejectsUnexpectedAndContradictoryEvidence(t *testing.T) {
	jobs := boundJobs()[:1]
	tracker, _ := NewTracker("run", jobs)
	tracker.Attempt(jobs[0])
	tracker.Started(jobs[0])
	tracker.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, SentBytes: 10, ReceivedBytes: 20, ActivityEvents: 1})
	report := tracker.Snapshot("completed")
	report.Modes[config.ExecutionMode("unexpected-id-like-key")] = Counts{}
	if _, err := Aggregate("run", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": report}); err == nil {
		t.Fatal("expected unexpected mode rejection")
	}
	report = tracker.Snapshot("completed")
	evidence := report.DimensionEvidence["ssh/direct"]
	evidence.SentBytes++
	report.DimensionEvidence["ssh/direct"] = evidence
	if _, err := Aggregate("run", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": report}); err == nil {
		t.Fatal("expected contradictory evidence rejection")
	}
}

func TestAggregateRejectsReportSchemaAndBuildMismatch(t *testing.T) {
	jobs := boundJobs()[:1]
	tracker, _ := NewTrackerWithBuildVersion("run", "build-1", jobs)
	tracker.Attempt(jobs[0])
	tracker.Started(jobs[0])
	tracker.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
	report := tracker.Snapshot("completed")
	expected := map[string][]config.Job{"agent": jobs}
	if _, err := AggregateForBuild("run", "build-1", expected, map[string]Report{"agent": report}); err != nil {
		t.Fatal(err)
	}
	badSchema := report
	badSchema.Version++
	if _, err := AggregateForBuild("run", "build-1", expected, map[string]Report{"agent": badSchema}); err == nil {
		t.Fatal("expected report schema mismatch rejection")
	}
	if _, err := AggregateForBuild("run", "build-2", expected, map[string]Report{"agent": report}); err == nil {
		t.Fatal("expected report build mismatch rejection")
	}
}

func TestAggregateRequiresPerSessionActivityEvidence(t *testing.T) {
	jobs := boundJobs()[:2]
	tracker, _ := NewTracker("run", jobs)
	for _, job := range jobs {
		tracker.Attempt(job)
		tracker.Started(job)
	}
	tracker.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, ActivityEvents: 2})
	tracker.Record(jobs[1], session.Observation{ConnectLatency: time.Millisecond})
	report := tracker.Snapshot("completed")
	if _, err := Aggregate("run", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": report}); err == nil {
		t.Fatal("expected inactive maintained session rejection")
	}
}

func TestAggregateConnectionOnlyAcceptsMaintainedReadOnlySessions(t *testing.T) {
	jobs := boundJobs()[:1]
	tracker, err := NewTracker("idle", jobs)
	if err != nil {
		t.Fatal(err)
	}
	tracker.Attempt(jobs[0])
	tracker.Started(jobs[0])
	tracker.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, ReceivedBytes: 1, LastActivity: time.Now()})
	if _, err := AggregateConnectionOnlyForBuild("idle", "dev", map[string][]config.Job{"agent": jobs}, map[string]Report{"agent": tracker.Snapshot("completed")}); err != nil {
		t.Fatalf("connection-only aggregate rejected maintained read-only session: %v", err)
	}
}

func TestAggregateTerminalPreservesFailedAgentCounts(t *testing.T) {
	jobs := boundJobs()[:2]
	reports := make(map[string]Report)
	expected := map[string][]config.Job{"agent-a": {jobs[0]}, "agent-b": {jobs[1]}}
	for index, agent := range []string{"agent-a", "agent-b"} {
		tracker, err := NewTrackerWithBuildVersion("terminal-run", "build-1", expected[agent])
		if err != nil {
			t.Fatal(err)
		}
		job := jobs[index]
		tracker.Attempt(job)
		tracker.Started(job)
		tracker.Record(job, session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
		status := "completed"
		if index == 0 {
			tracker.RuntimeFailed(job)
			status = "failed"
		}
		reports[agent] = tracker.Snapshot(status)
	}

	report, err := AggregateTerminalForBuild("terminal-run", "build-1", expected, reports, "failed")
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.Totals.Planned != 2 || report.Totals.RuntimeFailures != 1 || report.Totals.Maintained != 1 || len(report.Agents) != 2 {
		t.Fatalf("report=%+v", report)
	}
}

func TestAggregateTerminalRejectsUnexpectedDimensionsAndEvidence(t *testing.T) {
	jobs := boundJobs()[:1]
	expected := map[string][]config.Job{"agent": jobs}
	newReport := func() Report {
		tracker, err := NewTrackerWithBuildVersion("terminal-strict", "build-1", jobs)
		if err != nil {
			t.Fatal(err)
		}
		tracker.Attempt(jobs[0])
		tracker.Started(jobs[0])
		tracker.Record(jobs[0], session.Observation{ConnectLatency: time.Millisecond, SentBytes: 1, ReceivedBytes: 1, ActivityEvents: 1, LastActivity: time.Now()})
		tracker.RuntimeFailed(jobs[0])
		return tracker.Snapshot("failed")
	}

	for name, mutate := range map[string]func(*Report){
		"unexpected protocol":  func(report *Report) { report.Protocols[config.RDP] = Counts{} },
		"unexpected mode":      func(report *Report) { report.Modes[config.Browser] = Counts{} },
		"unexpected dimension": func(report *Report) { report.Dimensions["rdp/browser"] = Counts{} },
		"unexpected evidence":  func(report *Report) { report.DimensionEvidence["rdp/browser"] = Measurements{} },
		"wrong planned protocol": func(report *Report) {
			counts := report.Protocols[config.SSH]
			counts.Planned++
			report.Protocols[config.SSH] = counts
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := newReport()
			mutate(&report)
			if _, err := AggregateTerminalForBuild("terminal-strict", "build-1", expected, map[string]Report{"agent": report}, "failed"); err == nil {
				t.Fatal("expected strict terminal report rejection")
			}
		})
	}
}
