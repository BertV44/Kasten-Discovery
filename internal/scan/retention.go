package scan

// retentionAnalysis: the three retention shapes that cost a customer either
// recoverability or storage, read straight off the policy specs.
//
// Every one of them is a reading with a stated threshold, not a judgement --
// which is why they can be computed here while bestPractices, which turns them
// into a verdict, still cannot.

import (
	"sort"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
)

// highSnapshotRetention is KDL.sh's threshold, and its history is the reason it
// is a named constant rather than a literal: it was > 2, which flagged every
// standard daily-7 policy in existence, and the resulting warning was noise on
// every report. 7 is the typical maximum weekly retention for a legitimate
// daily policy. It is empirical, and the report says so next to the count.
const highSnapshotRetention = 7

// buildRetentionAnalysis inspects application policies only. The DR and reports
// policies K10 installs itself carry retention nobody chose and nobody can
// change, so counting them produces a finding no reader can act on.
func buildRetentionAnalysis(r *kdl.Report) {
	var (
		high   []kdl.RetentionAnalysisSnapshotRetentionHighItem
		zero   []string
		noExpR []string
	)

	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) {
			continue
		}

		if hasAction(p.Actions, "backup") {
			tiers := retentionTiers(p.Retention)
			max := 0
			for _, v := range tiers {
				if v > max {
					max = v
				}
			}
			switch {
			case max > highSnapshotRetention:
				high = append(high, kdl.RetentionAnalysisSnapshotRetentionHighItem{Name: p.Name, Max: max})
			case max == 0:
				// Every tier zero and no tier at all are the same finding: the
				// policy keeps no local snapshot, so there is no fast recovery
				// path and every restore has to come back from the export target.
				zero = append(zero, p.Name)
			}
		}

		// One export without retention is the finding, not all of them. Since
		// Kasten 9.0 a policy can carry two export actions, and if only one
		// declares retention the other still silently inherits the snapshot
		// retention -- KDL.sh's `all` form passed such a policy as compliant,
		// hiding exactly the case the check exists for.
		if hasAction(p.Actions, "export") {
			for _, e := range p.Exports {
				if e.Retention == nil {
					noExpR = append(noExpR, p.Name)
					break
				}
			}
			// A policy whose export actions were not modelled at all cannot be
			// cleared: it declares an export the report knows nothing about.
			if len(p.Exports) == 0 {
				noExpR = append(noExpR, p.Name)
			}
		}
	}

	sort.Slice(high, func(i, j int) bool { return high[i].Name < high[j].Name })
	sort.Strings(zero)
	sort.Strings(noExpR)

	r.RetentionAnalysis = kdl.RetentionAnalysis{
		SnapshotRetentionHigh: kdl.RetentionAnalysisSnapshotRetentionHigh{
			Count: len(high), Items: high,
			Note: "Policies with at least one snapshot retention key > 7 " +
				"(source storage I/O impact at high simultaneous snapshot counts)",
		},
		SnapshotRetentionZero: kdl.RetentionAnalysisSnapshotRetentionZero{
			Count: len(zero), Items: zero,
			Note: "Policies with no/zero snapshot retention (no fast local recovery)",
		},
		ExportWithoutExplicitRetention: kdl.RetentionAnalysisExportWithoutExplicitRetention{
			Count: len(noExpR), Items: noExpR,
			Note: "Export action inherits snapshot retention when no .retention is set on the export action",
		},
	}
}

// retentionTiers lists the retention values of a policy. hourly is included
// because it is a valid Kasten tier: leaving it out would report an @hourly
// policy keeping 48 snapshots as keeping none.
func retentionTiers(r kdl.PoliciesItemRetention) []int {
	return []int{r.Hourly, r.Daily, r.Weekly, r.Monthly, r.Yearly}
}
