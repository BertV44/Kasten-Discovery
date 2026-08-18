package scan

// policyRunStats: what the policies actually did, as opposed to what they are
// configured to do.
//
// Every figure here comes from RunActions -- the per-policy run records, which
// carry the start and end times the per-object actions do not. RunActions were
// deliberately absent from the collection plan until this file existed: the plan
// says an unused read costs API load and RBAC surface for nothing, so the read
// goes in with the code that consumes it.

import (
	"sort"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// rpoWindow is the 14 days KDL.sh samples. Two weeks covers a weekly policy
// twice over while staying inside the retention of most action histories -- K10
// garbage-collects action objects, so a longer window silently samples fewer
// policies rather than more runs.
const rpoWindow = 14 * 24 * time.Hour

// driftFactor is KDL.sh's empirical threshold: a median interval more than half
// again the declared frequency is scheduler or executor pressure rather than
// jitter. It is stated in the report next to the verdict it produced.
const driftFactor = 1.5

// frequencySeconds maps a K10 frequency alias to its theoretical interval.
//
// A policy with a custom cron expression is absent from this table on purpose,
// and that is not the same as a policy with no frequency: both get their
// intervals measured and reported, but neither gets a drift verdict, because
// there is no declared interval to be late against. Guessing one from a cron
// string would produce a confident verdict on an interval nobody declared.
//
// The 30-day month is K10's documented convention for @monthly, not a
// calendar-aware calculation.
var frequencySeconds = map[string]int{
	"@hourly":  3600,
	"@daily":   86400,
	"@weekly":  604800,
	"@monthly": 2592000,
	"@yearly":  31536000,
}

// buildPolicyRunStats fills all three of policyRunStats. They share one input
// and one hazard: a RunAction names its policy in spec.subject.name, and a run
// whose subject cannot be read belongs to no policy rather than to all of them.
func buildPolicyRunStats(res Result, r *kdl.Report, now time.Time) {
	runsByPolicy := map[string][]run{}
	for _, o := range res.Items("runActions") {
		subject, ok := str(o.Object, "spec", "subject", "name")
		if !ok || subject == "" {
			continue
		}
		runsByPolicy[subject] = append(runsByPolicy[subject], run{
			timestamp: creationTimestamp(o),
			state:     strOr(o.Object, "Unknown", "status", "state"),
			duration:  runDuration(o),
			errMsg:    deepestMessage(mapAt(o.Object, "status", "error")),
		})
	}
	for _, runs := range runsByPolicy {
		sort.Slice(runs, func(i, j int) bool { return runs[i].timestamp < runs[j].timestamp })
	}

	buildLastRuns(r, runsByPolicy)
	buildAverageDuration(r, runsByPolicy, now)
	buildEffectiveRPO(r, runsByPolicy, now)
}

// run is one RunAction, reduced to what the three sub-sections need.
type run struct {
	timestamp string
	state     string
	// duration is nil when the run record carries no start or end time, which is
	// the case while it is still running and on some cancelled runs. Zero would
	// claim it finished instantly.
	duration *int
	errMsg   string
}

func (r run) complete() bool { return r.state == stateComplete }

// runDuration is endTime - startTime, absent unless both are present and
// parsable. KDL.sh emits null there and so does this: a run still in flight has
// no duration, and zero would claim it finished instantly.
func runDuration(o unstructured.Unstructured) *int {
	start, okStart := str(o.Object, "status", "startTime")
	end, okEnd := str(o.Object, "status", "endTime")
	if !okStart || !okEnd {
		return nil
	}
	from, errA := time.Parse(time.RFC3339, start)
	to, errB := time.Parse(time.RFC3339, end)
	if errA != nil || errB != nil {
		return nil
	}
	secs := int(to.Sub(from).Seconds())
	if secs < 0 {
		return nil
	}
	return &secs
}

// buildLastRuns records the most recent run of every policy, including the
// policies that have never run: an empty lastRun is the finding, and dropping
// the row would hide it.
func buildLastRuns(r *kdl.Report, runsByPolicy map[string][]run) {
	out := make([]kdl.PolicyRunStatsLastRun, 0, len(r.Policies.Items))
	for _, p := range r.Policies.Items {
		entry := kdl.PolicyRunStatsLastRun{Name: p.Name}
		if runs := runsByPolicy[p.Name]; len(runs) > 0 {
			last := runs[len(runs)-1]
			e := &kdl.PolicyRunStatsLastRunEntry{
				Timestamp: last.timestamp,
				State:     last.state,
				Duration:  last.duration,
			}
			// The error is attached only to a failed run. On a successful one a
			// leftover message would read as a failure nobody had.
			if last.state == stateFailed && last.errMsg != "" {
				msg := last.errMsg
				e.Error = &msg
			}
			entry.LastRun = e
		}
		out = append(out, entry)
	}
	r.PolicyRunStats.LastRuns = out
}

// buildAverageDuration samples completed runs inside the window. It is reported
// with its sample count because an average over two runs and an average over
// two hundred are not the same claim.
func buildAverageDuration(r *kdl.Report, runsByPolicy map[string][]run, now time.Time) {
	var durations []int
	for _, runs := range runsByPolicy {
		for _, run := range runs {
			if !run.complete() || run.duration == nil || !within(run.timestamp, now, rpoWindow) {
				continue
			}
			durations = append(durations, *run.duration)
		}
	}
	if len(durations) == 0 {
		return
	}
	total, min, max := 0, durations[0], durations[0]
	for _, d := range durations {
		total += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	r.PolicyRunStats.AverageDuration = kdl.PolicyRunStatsAverageDuration{
		Seconds:     total / len(durations),
		Min:         min,
		Max:         max,
		SampleCount: len(durations),
	}
}

// buildEffectiveRPO measures the interval between consecutive successful runs
// per policy, which is the only figure in the report that says what the recovery
// point objective actually is rather than what it was configured to be.
//
// Failed, cancelled and running attempts are excluded: an RPO is the gap between
// two restorable points, and a failed run produced none. That is also why the
// figure can be far worse than the declared frequency on a cluster whose runs
// mostly fail -- which is the finding.
func buildEffectiveRPO(r *kdl.Report, runsByPolicy map[string][]run, now time.Time) {
	items := make([]kdl.PolicyRunStatsEffectiveRPOItem, 0, len(r.Policies.Items))
	withFreq, withSamples, inDrift := 0, 0, 0

	for _, p := range r.Policies.Items {
		item := kdl.PolicyRunStatsEffectiveRPOItem{Name: p.Name}
		item.FrequencyDeclared = p.Frequency

		var theoretical *int
		if p.Frequency != nil {
			if secs, known := frequencySeconds[*p.Frequency]; known {
				theoretical = &secs
				item.FrequencyTheoreticalSeconds = &secs
				withFreq++
			}
		}

		var stamps []time.Time
		for _, run := range runsByPolicy[p.Name] {
			if !run.complete() || !within(run.timestamp, now, rpoWindow) {
				continue
			}
			if t, err := time.Parse(time.RFC3339, run.timestamp); err == nil {
				stamps = append(stamps, t)
			}
		}
		sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })

		intervals := make([]int, 0, len(stamps))
		for i := 1; i < len(stamps); i++ {
			intervals = append(intervals, int(stamps[i].Sub(stamps[i-1]).Seconds()))
		}
		item.Samples = len(intervals)
		if len(intervals) > 0 {
			withSamples++
			med := median(intervals)
			item.Median = &med
			max := intervals[0]
			for _, v := range intervals {
				if v > max {
					max = v
				}
			}
			item.Max = &max
		}

		// Drift needs a declared interval and at least two measured ones. One
		// interval is not a rate: a policy that ran twice in a fortnight has a
		// median of nothing in particular, and calling it drifted from a single
		// gap would flag every newly created policy.
		if theoretical != nil && len(intervals) >= 2 {
			drift := *item.Median > float64(*theoretical)*driftFactor
			item.Drift = &drift
			if drift {
				inDrift++
			}
		}

		items = append(items, item)
	}

	r.PolicyRunStats.EffectiveRPO = kdl.PolicyRunStatsEffectiveRPO{
		Summary: kdl.PolicyRunStatsEffectiveRPOSummary{
			TotalPolicies:      len(items),
			WithKnownFrequency: withFreq,
			WithEnoughSamples:  withSamples,
			InDrift:            inDrift,
			DriftThreshold:     "median > theoretical × 1.5",
			Window:             "14 days",
			Note: "Median interval between consecutive successful (Complete) RunActions per policy. " +
				"Custom cron expressions are reported with stats but no drift judgement.",
		},
		Items: items,
	}
}

// median is the central tendency KDL.sh reports, and it is a median rather than
// a mean deliberately: one 12-hour backup after a maintenance window would drag
// a mean past the drift threshold on an otherwise punctual policy.
func median(v []int) float64 {
	s := append([]int(nil), v...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2])
	}
	return float64(s[n/2-1]+s[n/2]) / 2
}

// within reports whether a timestamp falls inside the sampling window. An
// unparsable timestamp is outside it: a run we cannot date cannot be placed in
// a sequence, and including it would put an interval of unknown length in the
// measurements.
func within(ts string, now time.Time, window time.Duration) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	return !t.Before(now.Add(-window))
}
