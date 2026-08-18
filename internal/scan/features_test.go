package scan

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// drPolicy builds the policy K10 installs to protect its own catalog.
func drPolicy(spec map[string]any) unstructured.Unstructured {
	return policy(drPolicyName, spec)
}

// quickDR is the modern shape: a kdrSnapshotConfiguration and a backup action
// carrying the profile.
func quickDR() unstructured.Unstructured {
	return drPolicy(map[string]any{
		"frequency": "@daily",
		"actions": []any{map[string]any{
			"action":           "backup",
			"backupParameters": map[string]any{"profile": map[string]any{"name": "dr-target"}},
		}},
		"kdrSnapshotConfiguration": map[string]any{
			"enabled":    true,
			"exportData": map[string]any{"enabled": true},
		},
	})
}

// TestDRVerdictComesFromTheRunHistoryNotThePolicy is the whole point of the
// section. An installed DR policy that has never completed protects nothing, and
// "enabled" over that is the most expensive false reassurance in the report:
// the customer finds out while trying to get the catalog back.
func TestDRVerdictComesFromTheRunHistoryNotThePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runs   []unstructured.Unstructured
		status string
	}{
		{
			name:   "never ran",
			runs:   nil,
			status: drNotHealthy,
		},
		{
			name:   "last run failed",
			runs:   []unstructured.Unstructured{runAction("r1", drPolicyName, stateFailed, ago(time.Hour), "", "")},
			status: drNotHealthy,
		},
		{
			name: "succeeded but months ago",
			runs: []unstructured.Unstructured{
				runAction("r1", drPolicyName, stateComplete, ago(60*24*time.Hour), "", ""),
			},
			status: drNotHealthy,
		},
		{
			name: "succeeded recently",
			runs: []unstructured.Unstructured{
				runAction("r1", drPolicyName, stateComplete, ago(6*time.Hour), "", ""),
			},
			status: drEnabled,
		},
		{
			name: "a later failure does not erase a recent success",
			runs: []unstructured.Unstructured{
				runAction("r1", drPolicyName, stateComplete, ago(6*time.Hour), "", ""),
				runAction("r2", drPolicyName, stateRunning, ago(time.Minute), "", ""),
			},
			status: drEnabled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := buildAt(t, map[string][]unstructured.Unstructured{
				"policies":   {quickDR()},
				"runactions": tc.runs,
			})
			if !r.DisasterRecovery.Enabled {
				t.Fatal("enabled = false, but the DR policy exists")
			}
			if r.DisasterRecovery.Status != tc.status {
				t.Errorf("status = %q, want %q", r.DisasterRecovery.Status, tc.status)
			}
		})
	}
}

// TestDRProfileComesFromWhicheverActionCarriesIt: modern DR puts the profile on
// a backup action. Reading only exportParameters showed a configured DR as
// having no target at all.
func TestDRProfileComesFromWhicheverActionCarriesIt(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies":   {quickDR()},
		"runactions": {runAction("r1", drPolicyName, stateComplete, ago(time.Hour), "", "")},
	})
	if got := r.DisasterRecovery.Profile; got != "dr-target" {
		t.Errorf("profile = %q, want dr-target from backupParameters", got)
	}
	if got := r.DisasterRecovery.Mode; got != "Quick DR (Local Catalog Snapshot)" {
		t.Errorf("mode = %q, want the local-snapshot mode", got)
	}
}

// TestDRWithNoInlineProfileSaysWhy: a DR export target is configured outside the
// policy, so a healthy DR legitimately has no profile to show. A bare "N/A"
// sends an operator hunting for a broken reference that never existed.
func TestDRWithNoInlineProfileSaysWhy(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {drPolicy(map[string]any{
			"frequency":                "@daily",
			"actions":                  []any{map[string]any{"action": "backup"}},
			"kdrSnapshotConfiguration": map[string]any{"enabled": false},
		})},
		"runactions": {runAction("r1", drPolicyName, stateComplete, ago(time.Hour), "", "")},
	})

	if got := r.DisasterRecovery.Mode; got != "Quick DR (No Catalog Snapshot)" {
		t.Fatalf("mode = %q, want the no-snapshot mode", got)
	}
	if got := r.DisasterRecovery.Profile; got == naValue {
		t.Error("profile is a bare N/A; the reason the target is not inline belongs in the value")
	}
	// And it is still healthy: the verdict must not be gated on the mode or on
	// an inline profile, which reported working clusters as incomplete.
	if r.DisasterRecovery.Status != drEnabled {
		t.Errorf("status = %q, want %q: a successful DR run is healthy whatever its mode",
			r.DisasterRecovery.Status, drEnabled)
	}
}

// TestNoDRPolicyIsNotEnabledRatherThanUnhealthy: the two verdicts prompt
// different actions -- one is "install DR", the other "fix DR".
func TestNoDRPolicyIsNotEnabledRatherThanUnhealthy(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {policy("app-daily", map[string]any{"frequency": "@daily"})},
	})
	dr := r.DisasterRecovery
	if dr.Enabled || dr.Status != drNotEnabled {
		t.Errorf("dr = %+v, want disabled with status %q", dr, drNotEnabled)
	}
	if dr.Mode != "Not Configured" || dr.LastRunState != "None" {
		t.Errorf("dr = %+v, want mode 'Not Configured' and lastRunState 'None'", dr)
	}
}

// TestDRIsDeclaredUnpopulatedWhenTheRunHistoryIsUnreadable: without the
// declaration, a scan that cannot read RunActions reports CONFIGURED_NOT_HEALTHY
// on a perfectly healthy DR -- and kdl diff calls that a new regression.
func TestDRIsDeclaredUnpopulatedWhenTheRunHistoryIsUnreadable(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{"policies": {quickDR()}},
		errs:  map[string]error{"runactions": forbidden("runactions")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	if !r.NotCollected("disasterRecovery") {
		t.Error("disasterRecovery is not declared unpopulated, but its run history was denied")
	}
}

// TestPrometheusDetectionIsScopedToTheK10Chart: a cluster-wide search for
// Prometheus matches OpenShift's own cluster monitoring on every OpenShift
// cluster, so the check passed regardless of whether K10 monitoring existed.
func TestPrometheusDetectionIsScopedToTheK10Chart(t *testing.T) {
	pod := func(name string, labels map[string]any, phase string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": name, "namespace": "kasten-io", "labels": labels},
			"status":     map[string]any{"phase": phase},
		}}
	}

	for _, tc := range []struct {
		name string
		pods []unstructured.Unstructured
		want bool
	}{
		{
			name: "legacy chart label",
			pods: []unstructured.Unstructured{pod("p", map[string]any{"app": "prometheus"}, "Running")},
			want: true,
		},
		{
			name: "current chart labels",
			pods: []unstructured.Unstructured{pod("p", map[string]any{
				"app.kubernetes.io/name":     "prometheus",
				"app.kubernetes.io/instance": "k10",
			}, "Running")},
			want: true,
		},
		{
			name: "a prometheus that is not K10's",
			pods: []unstructured.Unstructured{pod("p", map[string]any{
				"app.kubernetes.io/name":     "prometheus",
				"app.kubernetes.io/instance": "openshift-monitoring",
			}, "Running")},
			want: false,
		},
		{
			name: "present but not running",
			pods: []unstructured.Unstructured{pod("p", map[string]any{"app": "prometheus"}, "Pending")},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := buildAt(t, map[string][]unstructured.Unstructured{"pods": tc.pods})
			if r.Monitoring.Prometheus != tc.want {
				t.Errorf("prometheus = %v, want %v", r.Monitoring.Prometheus, tc.want)
			}
		})
	}
}
