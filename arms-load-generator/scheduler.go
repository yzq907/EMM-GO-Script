package main

import (
	"context"
	"time"
)

const schedulerInterval = 10 * time.Millisecond

func currentTargetTPS(target int, elapsed, rampUp time.Duration) int {
	if target <= 0 {
		return 0
	}
	if rampUp <= 0 || elapsed >= rampUp {
		return target
	}
	if elapsed <= 0 {
		return 0
	}
	return int(float64(target) * float64(elapsed) / float64(rampUp))
}

func permitsForTick(target int, elapsed, rampUp, tick time.Duration, carry float64) (int, float64) {
	effectiveTarget := currentTargetTPS(target, elapsed, rampUp)
	desired := float64(effectiveTarget)*tick.Seconds() + carry
	count := int(desired)
	return count, desired - float64(count)
}

func runScheduler(ctx context.Context, target int, rampUp, tick time.Duration, permits chan<- struct{}, stats *Stats) {
	if target <= 0 {
		<-ctx.Done()
		return
	}
	started := time.Now()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	carry := 0.0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			elapsed := now.Sub(started)
			stats.ScheduledTPS.Store(int64(currentTargetTPS(target, elapsed, rampUp)))
			var count int
			count, carry = permitsForTick(target, elapsed, rampUp, tick, carry)
			for range count {
				select {
				case <-ctx.Done():
					return
				case permits <- struct{}{}:
				default:
					stats.SchedulerBacklog.Add(1)
				}
			}
		}
	}
}
