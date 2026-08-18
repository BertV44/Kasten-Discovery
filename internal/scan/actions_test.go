package scan

import (
	"testing"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// testNow is the instant every age in these tests is measured from, so a test
// that passes today still passes in a year.
var testNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) string { return testNow.Add(-d).Format(time.RFC3339) }

// action builds a K10 action object. The appNamespace label is how K10 records
// which namespace was acted on -- the object itself always lives in kasten-io.
func action(kind, name, appNS, policy, state, created string, extra map[string]any) unstructured.Unstructured {
	labels := map[string]any{}
	if appNS != "" {
		labels[appNamespaceLabel] = appNS
	}
	if policy != "" {
		labels[policyNameLabel] = policy
	}
	o := map[string]any{
		"apiVersion": "actions.kio.kasten.io/v1alpha1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":              name,
			"namespace":         "kasten-io",
			"labels":            labels,
			"creationTimestamp": created,
		},
		"status": map[string]any{"state": state},
	}
	for k, v := range extra {
		o[k] = v
	}
	return unstructured.Unstructured{Object: o}
}

// buildAt builds a report with a fixed collection time.
func buildAt(t *testing.T, lists map[string][]unstructured.Unstructured) *kdl.Report {
	t.Helper()
	res := collect(t, &fakeReader{lists: lists})
	res.CollectedAt = testNow
	return Build(res)
}

// TestFailedActionsAreAttributedToTheNamespaceTheyActedOn is the hazard every
// section in actions.go shares: a K10 action object lives in the install
// namespace, so keying it by metadata.namespace files the whole cluster's work
// under kasten-io.
func TestFailedActionsAreAttributedToTheNamespaceTheyActedOn(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"backupactions": {
			action("BackupAction", "backup-a", "team-payments", "daily", stateFailed, ago(time.Hour), nil),
		},
	})

	if r.FailedActionsTop5.Count != 1 {
		t.Fatalf("failed actions = %d, want 1", r.FailedActionsTop5.Count)
	}
	got := r.FailedActionsTop5.Items[0]
	if got.Namespace != "team-payments" {
		t.Errorf("namespace = %q, want team-payments: the action was filed under the install namespace", got.Namespace)
	}
	if got.Kind != "BackupAction" || got.Policy != "daily" {
		t.Errorf("kind/policy = %q/%q, want BackupAction/daily", got.Kind, got.Policy)
	}
}

// TestFailedActionsTakeTheFiveNewestAcrossAllKinds: the list is one ranking over
// backups, exports and restores together, not five of each.
func TestFailedActionsTakeTheFiveNewestAcrossAllKinds(t *testing.T) {
	var backups []unstructured.Unstructured
	for i, d := range []time.Duration{9 * time.Hour, 8 * time.Hour, 7 * time.Hour, 6 * time.Hour, 5 * time.Hour} {
		backups = append(backups, action("BackupAction", "old-"+string(rune('a'+i)), "app", "p", stateFailed, ago(d), nil))
	}
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"backupactions": backups,
		"exportactions": {
			action("ExportAction", "newest-export", "app", "p", stateFailed, ago(time.Minute), nil),
		},
	})

	if len(r.FailedActionsTop5.Items) != 5 {
		t.Fatalf("items = %d, want 5", len(r.FailedActionsTop5.Items))
	}
	if r.FailedActionsTop5.Items[0].Name != "newest-export" {
		t.Errorf("first item = %q, want newest-export: the list is not sorted newest-first across kinds",
			r.FailedActionsTop5.Items[0].Name)
	}
}

// TestFailedActionMessageIsTheInnermostCause: the outer message says "backup
// failed", which the reader already knows. Only the innermost one names the
// failure, and K10 sometimes encodes a level as a JSON string.
func TestFailedActionMessageIsTheInnermostCause(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"backupactions": {
			action("BackupAction", "b", "app", "p", stateFailed, ago(time.Hour), map[string]any{
				"status": map[string]any{
					"state": stateFailed,
					"error": map[string]any{
						"message": "backup failed",
						"cause":   `{"message":"snapshot failed","cause":{"message":"csi driver timed out"}}`,
					},
				},
			}),
		},
	})

	if len(r.FailedActionsTop5.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(r.FailedActionsTop5.Items))
	}
	if got := r.FailedActionsTop5.Items[0].Message; got != "csi driver timed out" {
		t.Errorf("message = %q, want the innermost cause %q", got, "csi driver timed out")
	}
}

// TestStuckActionsNeedTheThreshold: an action Running for an hour is a healthy
// backup in progress. Reporting it as stuck would make every scan taken during
// a backup window announce a problem.
func TestStuckActionsNeedTheThreshold(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"backupactions": {
			action("BackupAction", "in-flight", "app", "p", stateRunning, ago(time.Hour), nil),
			action("BackupAction", "wedged", "app", "p", stateRunning, ago(50*time.Hour), nil),
		},
	})

	if r.StuckActions.ThresholdHours != stuckActionThresholdHours {
		t.Errorf("thresholdHours = %d, want %d stated in the report",
			r.StuckActions.ThresholdHours, stuckActionThresholdHours)
	}
	if r.StuckActions.Count != 1 {
		t.Fatalf("stuck = %d, want 1: only the 50h action is stuck", r.StuckActions.Count)
	}
	got := r.StuckActions.Items[0]
	if got.Name != "wedged" {
		t.Errorf("stuck item = %q, want wedged", got.Name)
	}
	if got.AgeHours != 50 {
		t.Errorf("ageHours = %d, want 50", got.AgeHours)
	}
}

// TestNamespaceProtectionSeparatesStaleFromNeverBackedUp: the two are different
// findings. A namespace nobody ever backed up is a coverage gap; one backed up
// three weeks ago is a broken schedule, and they are fixed differently.
func TestNamespaceProtectionSeparatesStaleFromNeverBackedUp(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {
			obj("Namespace", "fresh-app", nil),
			obj("Namespace", "stale-app", nil),
			obj("Namespace", "never-app", nil),
			obj("Namespace", "kube-system", nil),
		},
		"backupactions": {
			action("BackupAction", "b1", "fresh-app", "p", stateComplete, ago(2*time.Hour), nil),
			action("BackupAction", "b2", "stale-app", "p", stateComplete, ago(21*24*time.Hour), nil),
			// A failed run must not count as protection: the namespace has no
			// usable restore point from it.
			action("BackupAction", "b3", "never-app", "p", stateFailed, ago(time.Hour), nil),
		},
	})

	nps := r.NamespaceProtectionStatus
	if nps.Total != 3 {
		t.Fatalf("total = %d, want 3 application namespaces (kube-system is a system namespace)", nps.Total)
	}
	byNS := map[string]kdl.NamespaceProtectionStatusItem{}
	for _, i := range nps.Items {
		byNS[i.Namespace] = i
	}

	if fresh := byNS["fresh-app"]; fresh.Stale || fresh.NeverBackedUp || fresh.LastBackup == nil {
		t.Errorf("fresh-app = %+v, want a recent backup and neither flag", fresh)
	}
	stale := byNS["stale-app"]
	if !stale.Stale || stale.NeverBackedUp {
		t.Errorf("stale-app = %+v, want stale and not neverBackedUp", stale)
	}
	if stale.BackupAgeDays == nil || *stale.BackupAgeDays != 21 {
		t.Errorf("stale-app backupAgeDays = %v, want 21", stale.BackupAgeDays)
	}
	never := byNS["never-app"]
	if !never.NeverBackedUp || never.LastBackup != nil {
		t.Errorf("never-app = %+v, want neverBackedUp with a null lastBackup: a failed run is not protection", never)
	}
	if never.Stale {
		t.Error("never-app is reported stale as well as never backed up; the two counts would double-count it")
	}
	if nps.Stale != 1 || nps.NeverBackedUp != 1 {
		t.Errorf("stale/never = %d/%d, want 1/1", nps.Stale, nps.NeverBackedUp)
	}
}

// TestNamespaceProtectionIgnoresTheInstallNamespaceFallback guards the bug
// KDL.sh shipped: grouping by metadata.namespace made every application
// namespace look untouched, because every action lives in kasten-io.
func TestNamespaceProtectionIgnoresTheInstallNamespaceFallback(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "app-a", nil)},
		"backupactions": {
			// No appNamespace label: the subject is unknown, and it is certainly
			// not app-a.
			action("BackupAction", "unlabelled", "", "p", stateComplete, ago(time.Hour), nil),
		},
	})

	if len(r.NamespaceProtectionStatus.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(r.NamespaceProtectionStatus.Items))
	}
	if item := r.NamespaceProtectionStatus.Items[0]; !item.NeverBackedUp {
		t.Errorf("app-a = %+v, want neverBackedUp: an unlabelled action is not evidence it was backed up", item)
	}
}

// TestOrphanedRestorePointsNeedTheirPolicyGone: the section is an accusation
// that a policy was deleted, so a live policy must never appear in it.
func TestOrphanedRestorePointsNeedTheirPolicyGone(t *testing.T) {
	rp := func(name, appNS, actionName string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apps.kio.kasten.io/v1alpha1",
			"kind":       "RestorePoint",
			"metadata": map[string]any{
				"name":              name,
				"namespace":         "kasten-io",
				"labels":            map[string]any{appNamespaceLabel: appNS},
				"creationTimestamp": ago(time.Hour),
			},
			"spec": map[string]any{"source": map[string]any{"actionName": actionName}},
		}}
	}

	r := buildAt(t, map[string][]unstructured.Unstructured{
		"policies": {policy("daily-backup", map[string]any{"frequency": "@daily"})},
		"restorepoints": {
			rp("rp-live", "app-a", "daily-backup-abc12-xyz34-99999"),
			rp("rp-orphan", "app-b", "deleted-policy-abc12-xyz34-99999"),
			// A name with nothing before the three generated segments cannot be
			// parsed; accusing it of orphanhood would be a guess.
			rp("rp-unparsable", "app-c", "abc-def-ghi"),
		},
	})

	if r.OrphanedRestorePoints.Count != 1 {
		t.Fatalf("orphaned = %d, want 1: %+v", r.OrphanedRestorePoints.Count, r.OrphanedRestorePoints.Items)
	}
	got := r.OrphanedRestorePoints.Items[0]
	if got.Name != "rp-orphan" {
		t.Errorf("orphan = %q, want rp-orphan", got.Name)
	}
	if got.Namespace != "app-b" {
		t.Errorf("namespace = %q, want app-b", got.Namespace)
	}
}

// TestRestorePointsByNamespaceRanksByCount, and ranks them by the namespace
// they belong to rather than the one they are stored in.
func TestRestorePointsByNamespaceRanksByCount(t *testing.T) {
	var rps []unstructured.Unstructured
	for i := 0; i < 7; i++ {
		rps = append(rps, action("RestorePoint", "rp-big-"+string(rune('a'+i)), "hoarder", "", "", ago(time.Hour), nil))
	}
	rps = append(rps, action("RestorePoint", "rp-small", "tidy", "", "", ago(time.Hour), nil))

	r := buildAt(t, map[string][]unstructured.Unstructured{"restorepoints": rps})

	top := r.RestorePointsByNamespace.Top5
	if len(top) != 2 {
		t.Fatalf("top5 = %d entries, want 2", len(top))
	}
	if top[0].Namespace != "hoarder" || top[0].Count != 7 {
		t.Errorf("first = %+v, want hoarder with 7", top[0])
	}
	if top[1].Namespace != "tidy" || top[1].Count != 1 {
		t.Errorf("second = %+v, want tidy with 1", top[1])
	}
}

// TestProfileValidationCountsBothSpellingsOfFailure: Kasten writes Failed on
// some releases and Failing on others, and counting one halves the figure the
// report leads with.
func TestProfileValidationCountsBothSpellingsOfFailure(t *testing.T) {
	prof := func(name string, status map[string]any) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "config.kio.kasten.io/v1alpha1",
			"kind":       "Profile",
			"metadata":   map[string]any{"name": name},
			"status":     status,
		}}
	}

	r := buildAt(t, map[string][]unstructured.Unstructured{
		"profiles": {
			prof("healthy", map[string]any{"validation": "Success"}),
			prof("broken", map[string]any{
				"validation": "Failed",
				"error":      map[string]any{"message": "AccessDenied: bucket policy"},
			}),
			prof("degrading", map[string]any{"validation": "Failing"}),
			prof("silent", map[string]any{}),
		},
	})

	pv := r.ProfileValidation
	if pv.FailedCount != 2 {
		t.Errorf("failedCount = %d, want 2: Failed and Failing both count", pv.FailedCount)
	}
	byName := map[string]kdl.ProfileValidationItem{}
	for _, i := range pv.Items {
		byName[i.Name] = i
	}
	if got := byName["silent"].State; got != "Unknown" {
		t.Errorf("profile with no status = %q, want Unknown rather than an empty string", got)
	}
	if got := byName["broken"].Error; got == nil || *got != "AccessDenied: bucket policy" {
		t.Errorf("broken error = %v, want the validation message", got)
	}
	if byName["healthy"].Error != nil {
		t.Errorf("healthy error = %v, want null", byName["healthy"].Error)
	}
}

// TestDeniedActionReadIsDeclaredNotEmpty is the point of the per-run
// unpopulated list. Without it a scan by a service account that cannot read
// BackupActions produces a report saying every namespace was never backed up,
// and `kdl diff` calls that a cluster-wide regression.
func TestDeniedActionReadIsDeclaredNotEmpty(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{
			"namespaces": {obj("Namespace", "app-a", nil)},
		},
		errs: map[string]error{"backupactions": forbidden("backupactions")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	for _, section := range []string{"namespaceProtectionStatus", "failedActionsTop5", "stuckActions"} {
		if !r.NotCollected(section) {
			t.Errorf("%s is not declared unpopulated, but the BackupAction read was denied; "+
				"its zero value is indistinguishable from a cluster with nothing in it", section)
		}
	}
	// Sections that did not depend on the denied read stay comparable.
	if r.NotCollected("profileValidation") {
		t.Error("profileValidation is declared unpopulated, but the profile read succeeded")
	}
}

// TestAbsentResourceIsNotDeclaredUnpopulated: a cluster that does not serve
// RestorePoints genuinely holds none, so zero is a fact. Declaring it unknown
// would make the section permanently undiffable on such a cluster.
func TestAbsentResourceIsNotDeclaredUnpopulated(t *testing.T) {
	served := map[string]bool{}
	for _, tg := range targets("kasten-io") {
		served[tg.gvr.Resource] = true
	}
	served["restorepoints"] = false

	res := collect(t, &fakeReader{served: served})
	res.CollectedAt = testNow
	r := Build(res)

	if r.NotCollected("restorePointsByNamespace") {
		t.Error("restorePointsByNamespace is declared unpopulated on a cluster that serves no RestorePoints; " +
			"absent and denied are different facts")
	}
}
