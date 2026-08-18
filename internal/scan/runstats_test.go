package scan

import (
	"testing"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// runAction builds a RunAction, the per-policy run record. It names its policy
// in spec.subject.name and is the only object carrying start and end times.
func runAction(name, policy, state, created string, start, end string) unstructured.Unstructured {
	status := map[string]any{"state": state}
	if start != "" {
		status["startTime"] = start
	}
	if end != "" {
		status["endTime"] = end
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "actions.kio.kasten.io/v1alpha1",
		"kind":       "RunAction",
		"metadata": map[string]any{
			"name":              name,
			"namespace":         "kasten-io",
			"creationTimestamp": created,
		},
		"spec":   map[string]any{"subject": map[string]any{"name": policy}},
		"status": status,
	}}
}

// TestEffectiveRPOMeasuresSuccessfulRunsOnly is the whole point of the section:
// an RPO is the gap between two restorable points, and a failed run produced
// none. A daily policy whose runs mostly fail has a real RPO of days.
func TestEffectiveRPOMeasuresSuccessfulRunsOnly(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {policy("daily", map[string]any{
			"frequency": "@daily",
			"actions":   []any{map[string]any{"action": "backup"}},
		})},
		"runactions": {
			runAction("r1", "daily", stateComplete, ago(96*time.Hour), "", ""),
			runAction("r2", "daily", stateFailed, ago(72*time.Hour), "", ""),
			runAction("r3", "daily", stateFailed, ago(48*time.Hour), "", ""),
			runAction("r4", "daily", stateComplete, ago(24*time.Hour), "", ""),
		},
	})

	items := r.PolicyRunStats.EffectiveRPO.Items
	if len(items) != 1 {
		t.Fatalf("effectiveRpo items = %d, want 1", len(items))
	}
	it := items[0]
	if it.Samples != 1 {
		t.Fatalf("samples = %d, want 1: two successful runs make one interval", it.Samples)
	}
	if it.Median == nil || *it.Median != 72*3600 {
		t.Errorf("median = %v, want 259200s: the two failed runs in between produced no restore point", it.Median)
	}
	if it.FrequencyTheoreticalSeconds == nil || *it.FrequencyTheoreticalSeconds != 86400 {
		t.Errorf("theoretical = %v, want 86400 for @daily", it.FrequencyTheoreticalSeconds)
	}
	// One interval is not a rate: a drift verdict off a single gap would flag
	// every policy created this week.
	if it.Drift != nil {
		t.Errorf("drift = %v, want null on a single interval", *it.Drift)
	}
}

// TestEffectiveRPODriftNeedsADeclaredInterval: a custom cron expression gets its
// intervals measured and reported, but no drift verdict. Guessing a theoretical
// interval from a cron string would produce a confident judgement about a
// schedule nobody declared.
func TestEffectiveRPODriftNeedsADeclaredInterval(t *testing.T) {
	runs := func(policyName string, hoursApart ...int) []unstructured.Unstructured {
		var out []unstructured.Unstructured
		for i, h := range hoursApart {
			out = append(out, runAction(
				policyName+"-r"+string(rune('a'+i)), policyName, stateComplete,
				ago(time.Duration(h)*time.Hour), "", ""))
		}
		return out
	}
	all := append(runs("cron", 300, 200, 100), runs("drifting", 300, 200, 100)...)

	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("cron", map[string]any{
				"frequency": "0 4 * * *",
				"actions":   []any{map[string]any{"action": "backup"}},
			}),
			policy("drifting", map[string]any{
				"frequency": "@daily",
				"actions":   []any{map[string]any{"action": "backup"}},
			}),
		},
		"runactions": all,
	})

	byName := map[string]kdl.PolicyRunStatsEffectiveRPOItem{}
	for _, it := range r.PolicyRunStats.EffectiveRPO.Items {
		byName[it.Name] = it
	}

	cron := byName["cron"]
	if cron.Samples != 2 {
		t.Errorf("cron samples = %d, want 2: stats are reported for custom schedules", cron.Samples)
	}
	if cron.FrequencyTheoreticalSeconds != nil {
		t.Errorf("cron theoretical = %v, want null: a cron string declares no single interval",
			*cron.FrequencyTheoreticalSeconds)
	}
	if cron.Drift != nil {
		t.Errorf("cron drift = %v, want null with no declared interval to be late against", *cron.Drift)
	}

	// 100h between daily runs is well past 24h × 1.5.
	drifting := byName["drifting"]
	if drifting.Drift == nil || !*drifting.Drift {
		t.Errorf("drifting drift = %v, want true: a daily policy running every 100h is in drift", drifting.Drift)
	}

	sum := r.PolicyRunStats.EffectiveRPO.Summary
	if sum.TotalPolicies != 2 || sum.WithKnownFrequency != 1 || sum.WithEnoughSamples != 2 || sum.InDrift != 1 {
		t.Errorf("summary = %+v, want 2 policies / 1 known frequency / 2 with samples / 1 in drift", sum)
	}
}

// TestEffectiveRPOIgnoresRunsOutsideTheWindow: the window is stated in the
// report, and a run older than it must not contribute an interval -- otherwise
// a policy that ran twice last year reports a median measured across the gap.
func TestEffectiveRPOIgnoresRunsOutsideTheWindow(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {policy("daily", map[string]any{
			"frequency": "@daily",
			"actions":   []any{map[string]any{"action": "backup"}},
		})},
		"runactions": {
			runAction("old", "daily", stateComplete, ago(40*24*time.Hour), "", ""),
			runAction("recent", "daily", stateComplete, ago(24*time.Hour), "", ""),
		},
	})

	it := r.PolicyRunStats.EffectiveRPO.Items[0]
	if it.Samples != 0 {
		t.Errorf("samples = %d, want 0: only one run falls inside the 14-day window", it.Samples)
	}
	if it.Median != nil || it.Max != nil {
		t.Errorf("median/max = %v/%v, want null with no interval measured", it.Median, it.Max)
	}
	if got := r.PolicyRunStats.EffectiveRPO.Summary.Window; got != "14 days" {
		t.Errorf("window = %q, want the report to state the window it measured", got)
	}
}

// TestLastRunKeepsPoliciesThatNeverRan: an empty lastRun is the finding. A
// policy configured but never executed is the most serious thing this section
// can report, and dropping the row hides it.
func TestLastRunKeepsPoliciesThatNeverRan(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("never-ran", map[string]any{"frequency": "@daily"}),
			policy("ran", map[string]any{"frequency": "@daily"}),
		},
		"runactions": {
			runAction("r1", "ran", stateFailed, ago(time.Hour),
				testNow.Add(-time.Hour).Format(time.RFC3339),
				testNow.Add(-30*time.Minute).Format(time.RFC3339)),
		},
	})

	byName := map[string]kdl.PolicyRunStatsLastRun{}
	for _, lr := range r.PolicyRunStats.LastRuns {
		byName[lr.Name] = lr
	}
	if len(byName) != 2 {
		t.Fatalf("lastRuns = %d entries, want 2", len(byName))
	}
	if byName["never-ran"].LastRun != nil {
		t.Error("a policy that never ran has a lastRun entry; null is the finding")
	}
	ran := byName["ran"].LastRun
	if ran == nil {
		t.Fatal("the policy that ran has no lastRun")
	}
	if ran.Duration == nil || *ran.Duration != 1800 {
		t.Errorf("duration = %v, want 1800s from endTime - startTime", ran.Duration)
	}
	if ran.State != stateFailed {
		t.Errorf("state = %q, want %q", ran.State, stateFailed)
	}
}

// TestLastRunErrorOnlyOnFailure: a leftover message on a successful run reads
// as a failure nobody had.
func TestLastRunErrorOnlyOnFailure(t *testing.T) {
	withError := func(name, policy, state string) unstructured.Unstructured {
		o := runAction(name, policy, state, ago(time.Hour), "", "")
		o.Object["status"].(map[string]any)["error"] = map[string]any{"message": "quota exceeded"}
		return o
	}
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("failed", map[string]any{"frequency": "@daily"}),
			policy("passed", map[string]any{"frequency": "@daily"}),
		},
		"runactions": {
			withError("r1", "failed", stateFailed),
			withError("r2", "passed", stateComplete),
		},
	})

	byName := map[string]kdl.PolicyRunStatsLastRun{}
	for _, lr := range r.PolicyRunStats.LastRuns {
		byName[lr.Name] = lr
	}
	if got := byName["failed"].LastRun.Error; got == nil || *got != "quota exceeded" {
		t.Errorf("failed run error = %v, want the message", got)
	}
	if got := byName["passed"].LastRun.Error; got != nil {
		t.Errorf("successful run error = %q, want null", *got)
	}
}

// TestAverageDurationNeedsBothTimestamps: a run with no endTime is still in
// flight. Counting it as a zero-second backup drags the average toward zero and
// makes a cluster with stuck runs look fast.
func TestAverageDurationNeedsBothTimestamps(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {policy("daily", map[string]any{"frequency": "@daily"})},
		"runactions": {
			runAction("done", "daily", stateComplete, ago(2*time.Hour),
				testNow.Add(-2*time.Hour).Format(time.RFC3339),
				testNow.Add(-time.Hour).Format(time.RFC3339)),
			runAction("in-flight", "daily", stateComplete, ago(time.Hour),
				testNow.Add(-time.Hour).Format(time.RFC3339), ""),
		},
	})

	avg := r.PolicyRunStats.AverageDuration
	if avg.SampleCount != 1 {
		t.Fatalf("sampleCount = %d, want 1: the run with no endTime has no duration", avg.SampleCount)
	}
	if avg.Seconds != 3600 || avg.Min != 3600 || avg.Max != 3600 {
		t.Errorf("avg/min/max = %d/%d/%d, want 3600 each", avg.Seconds, avg.Min, avg.Max)
	}
}

// TestRetentionAnalysisSeparatesTheThreeShapes, and excludes the policies K10
// installs itself: their retention is not the customer's to change, so a finding
// about it is one no reader can act on.
func TestRetentionAnalysisSeparatesTheThreeShapes(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("hoards-snapshots", map[string]any{
				"actions":   []any{map[string]any{"action": "backup"}},
				"retention": map[string]any{"daily": int64(7), "weekly": int64(30)},
			}),
			policy("no-local-recovery", map[string]any{
				"actions":   []any{map[string]any{"action": "backup"}},
				"retention": map[string]any{"daily": int64(0)},
			}),
			policy("sensible", map[string]any{
				"actions":   []any{map[string]any{"action": "backup"}},
				"retention": map[string]any{"daily": int64(7)},
			}),
			policy("k10-disaster-recovery-policy", map[string]any{
				"actions":   []any{map[string]any{"action": "backup"}},
				"retention": map[string]any{"daily": int64(99)},
			}),
		},
	})

	high := r.RetentionAnalysis.SnapshotRetentionHigh
	if high.Count != 1 {
		// The K10 DR policy also declares daily 99, so a count of 2 means the
		// system policies were not excluded -- and its retention is not the
		// customer's to change, so flagging it is a finding nobody can act on.
		t.Fatalf("high = %d, want just hoards-snapshots: %+v", high.Count, high.Items)
	}
	if high.Items[0].Name != "hoards-snapshots" || high.Items[0].Max != 30 {
		t.Errorf("high item = %+v, want hoards-snapshots with max 30", high.Items[0])
	}

	zero := r.RetentionAnalysis.SnapshotRetentionZero
	if zero.Count != 1 || zero.Items[0] != "no-local-recovery" {
		t.Errorf("zero = %+v, want just no-local-recovery", zero)
	}
}

// TestExportWithoutRetentionCatchesTheSecondExport is the Kasten 9.0 case the
// check exists for: a policy with two export actions where only one declares
// retention. The other still silently inherits the snapshot retention, and
// reading "the" export of a policy passes it as compliant.
func TestExportWithoutRetentionCatchesTheSecondExport(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("half-declared", map[string]any{
				"actions": []any{
					map[string]any{"action": "backup"},
					map[string]any{
						"action":           "export",
						"exportParameters": map[string]any{"profile": map[string]any{"name": "s3"}},
						"retention":        map[string]any{"daily": int64(30)},
					},
					map[string]any{
						"action":           "export",
						"exportParameters": map[string]any{"profile": map[string]any{"name": "vbr"}},
					},
				},
				"retention": map[string]any{"daily": int64(7)},
			}),
			policy("fully-declared", map[string]any{
				"actions": []any{
					map[string]any{"action": "backup"},
					map[string]any{
						"action":           "export",
						"exportParameters": map[string]any{"profile": map[string]any{"name": "s3"}},
						"retention":        map[string]any{"daily": int64(30)},
					},
				},
				"retention": map[string]any{"daily": int64(7)},
			}),
		},
	})

	got := r.RetentionAnalysis.ExportWithoutExplicitRetention
	if got.Count != 1 {
		t.Fatalf("exportWithoutExplicitRetention = %+v, want just half-declared", got)
	}
	if got.Items[0] != "half-declared" {
		t.Errorf("item = %q, want half-declared: the second export inherits snapshot retention", got.Items[0])
	}
}

// TestDeniedRunActionReadIsDeclaredNotEmpty: without the declaration, a scan
// that could not read RunActions reports every policy as never having run.
func TestDeniedRunActionReadIsDeclaredNotEmpty(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{
			"policies": {policy("daily", map[string]any{"frequency": "@daily"})},
		},
		errs: map[string]error{"runactions": forbidden("runactions")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	for _, section := range []string{
		"policyRunStats.lastRuns", "policyRunStats.averageDuration", "policyRunStats.effectiveRpo",
	} {
		if !r.NotCollected(section) {
			t.Errorf("%s is not declared unpopulated, but the RunAction read was denied; "+
				"the report claims every policy never ran", section)
		}
	}
	if r.NotCollected("retentionAnalysis") {
		t.Error("retentionAnalysis is declared unpopulated, but it needs only the policies read, which succeeded")
	}
}
