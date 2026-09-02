package distributed

import (
	"fmt"
	"sort"

	"pam-loadtest/internal/config"
)

type Agent struct {
	ID              string
	Capacity        int
	DirectCapacity  int
	BrowserCapacity int
	DirectProtocols []config.Protocol
}

func Partition(jobs []config.Job, agents []Agent) (map[string][]config.Job, error) {
	totalCapacity, directCapacity, browserCapacity := 0, 0, 0
	seenAgents := map[string]bool{}
	normalized := append([]Agent(nil), agents...)
	for index := range normalized {
		agent := &normalized[index]
		if agent.ID == "" || seenAgents[agent.ID] || agent.Capacity < 0 || agent.DirectCapacity < 0 || agent.BrowserCapacity < 0 {
			return nil, fmt.Errorf("invalid agent")
		}
		seenAgents[agent.ID] = true
		if agent.DirectCapacity == 0 {
			agent.DirectCapacity = agent.Capacity
		}
		totalCapacity += agent.Capacity
		directCapacity += agent.DirectCapacity
		browserCapacity += agent.BrowserCapacity
	}
	if totalCapacity < len(jobs) {
		return nil, fmt.Errorf("agent capacity %d is below %d jobs", totalCapacity, len(jobs))
	}

	directJobs := make([]config.Job, 0, len(jobs))
	browserJobs := make([]config.Job, 0, len(jobs))
	assets := make(map[string]struct{}, len(jobs))
	accounts := make(map[string]struct{}, len(jobs))
	for _, job := range jobs {
		mode := job.Mode
		if job.AssetID == "" || job.AccountID == "" {
			return nil, fmt.Errorf("job %d is missing an asset binding", job.ID)
		}
		if _, exists := assets[job.AssetID]; exists {
			return nil, fmt.Errorf("global asset assignment contains a duplicate")
		}
		if _, exists := accounts[job.AccountID]; exists {
			return nil, fmt.Errorf("global account assignment contains a duplicate")
		}
		assets[job.AssetID], accounts[job.AccountID] = struct{}{}, struct{}{}
		switch mode {
		case config.Direct:
			directJobs = append(directJobs, job)
		case config.Browser:
			browserJobs = append(browserJobs, job)
		default:
			return nil, fmt.Errorf("job %d has unsupported execution mode", job.ID)
		}
	}
	if directCapacity < len(directJobs) {
		return nil, fmt.Errorf("agent direct capacity %d is below %d jobs", directCapacity, len(directJobs))
	}
	if browserCapacity < len(browserJobs) {
		return nil, fmt.Errorf("agent browser capacity %d is below %d jobs", browserCapacity, len(browserJobs))
	}
	sort.SliceStable(directJobs, func(left, right int) bool {
		return supportingAgentCount(normalized, directJobs[left].Protocol) < supportingAgentCount(normalized, directJobs[right].Protocol)
	})

	result := make(map[string][]config.Job, len(normalized))
	totalUsed := make([]int, len(normalized))
	directUsed := make([]int, len(normalized))
	browserUsed := make([]int, len(normalized))
	assign := func(source []config.Job, browser bool) error {
		cursor := 0
		for _, job := range source {
			assigned := false
			for checked := 0; checked < len(normalized); checked++ {
				index := (cursor + checked) % len(normalized)
				agent := normalized[index]
				if totalUsed[index] >= agent.Capacity {
					continue
				}
				if browser && browserUsed[index] >= agent.BrowserCapacity {
					continue
				}
				if !browser && directUsed[index] >= agent.DirectCapacity {
					continue
				}
				if !browser && !supportsDirectProtocol(agent.DirectProtocols, job.Protocol) {
					continue
				}
				result[agent.ID] = append(result[agent.ID], job)
				totalUsed[index]++
				if browser {
					browserUsed[index]++
				} else {
					directUsed[index]++
				}
				cursor = (index + 1) % len(normalized)
				assigned = true
				break
			}
			if !assigned {
				return fmt.Errorf("agent %s capacity cannot satisfy deterministic partition", map[bool]string{true: "browser", false: "direct"}[browser])
			}
		}
		return nil
	}
	if len(normalized) == 0 && len(jobs) != 0 {
		return nil, fmt.Errorf("at least one agent is required")
	}
	if err := assign(directJobs, false); err != nil {
		return nil, err
	}
	if err := assign(browserJobs, true); err != nil {
		return nil, err
	}
	for _, agent := range normalized {
		if result[agent.ID] == nil {
			result[agent.ID] = []config.Job{}
		}
	}
	return result, nil
}

func supportingAgentCount(agents []Agent, protocol config.Protocol) int {
	count := 0
	for _, agent := range agents {
		if agent.DirectCapacity > 0 && supportsDirectProtocol(agent.DirectProtocols, protocol) {
			count++
		}
	}
	return count
}

func supportsDirectProtocol(supported []config.Protocol, protocol config.Protocol) bool {
	for _, candidate := range supported {
		if candidate == protocol {
			return true
		}
	}
	return false
}
