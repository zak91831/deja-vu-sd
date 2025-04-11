package timetravel

import (
	"fmt"
	"time"

	"github.com/dejavu/scanner/pkg/core/target"
)

// HistoricalTarget represents a target with historical context
type HistoricalTarget struct {
	*target.Target
	SnapshotDate time.Time
	Source       string // "wayback" or "certificate"
}

// NewHistoricalTarget creates a new historical target
func NewHistoricalTarget(target *target.Target, snapshotDate time.Time, source string) *HistoricalTarget {
	return &HistoricalTarget{
		Target:       target,
		SnapshotDate: snapshotDate,
		Source:       source,
	}
}

// FilterHistoricalTargets filters historical targets based on age
func FilterHistoricalTargets(targets []*HistoricalTarget, maxAgeDays int) []*HistoricalTarget {
	if maxAgeDays <= 0 {
		return targets
	}

	cutoffDate := time.Now().AddDate(0, 0, -maxAgeDays)
	filtered := make([]*HistoricalTarget, 0)

	for _, target := range targets {
		if target.SnapshotDate.After(cutoffDate) {
			filtered = append(filtered, target)
		}
	}

	return filtered
}

// DeduplicateHistoricalTargets removes duplicate historical targets
func DeduplicateHistoricalTargets(targets []*HistoricalTarget) []*HistoricalTarget {
	seen := make(map[string]bool)
	deduplicated := make([]*HistoricalTarget, 0)

	for _, target := range targets {
		key := fmt.Sprintf("%s:%s", target.URL, target.SnapshotDate.Format("2006-01-02"))
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, target)
		}
	}

	return deduplicated
}

// ConvertToRegularTargets converts historical targets to regular targets
func ConvertToRegularTargets(historicalTargets []*HistoricalTarget) []*target.Target {
	targets := make([]*target.Target, len(historicalTargets))
	
	for i, ht := range historicalTargets {
		targets[i] = ht.Target
	}
	
	return targets
}
