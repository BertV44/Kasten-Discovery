package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/BertV44/Kasten-Discovery/internal/report"
	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Regression tests for the four defects an independent audit found in the
// declaration machinery. Each one produced a report that was actively misleading
// rather than merely incomplete, and each was invisible to a passing test suite.

// TestDeniedPolicyReadDeclaresThePolicySectionItself was the worst of them. The
// thirteen sections DERIVED from policies were declared while the policy section
// itself was not, so the page said "no policy defined" next to checks that
// correctly said nothing had been assessed -- and kdl diff reported twelve
// policies removed from an unchanged cluster.
func TestDeniedPolicyReadDeclaresThePolicySectionItself(t *testing.T) {
	res := collect(t, &fakeReader{errs: map[string]error{
		"policies": forbidden("policies"),
		"profiles": forbidden("profiles"),
	}})
	res.CollectedAt = testNow
	r := Build(res)

	for _, section := range []string{
		"policies", "profiles", "coverage", "policyAnalysis",
		"importPolicies", "policiesWithoutExport",
	} {
		if !r.NotCollected(section) {
			t.Errorf("%q is not declared although its read was refused; the section renders "+
				"zeros as findings and kdl diff reports them as losses", section)
		}
	}
}

// TestDeniedActionReadDeclaresHealth: health counts finished actions, so a denied
// listing leaves it reporting zero backups and a success rate of N/A -- a cluster
// that has never run one.
func TestDeniedActionReadDeclaresHealth(t *testing.T) {
	res := collect(t, &fakeReader{errs: map[string]error{
		"backupactions": forbidden("backupactions"),
	}})
	res.CollectedAt = testNow

	if r := Build(res); !r.NotCollected("health") {
		t.Error("health is not declared although the BackupAction read was refused")
	}
}

// TestRefusedHelmReadDoesNotReportAnUnauthenticatedCluster.
//
// The k10-config ConfigMap almost always exists, so a refused Helm Secret read
// still left a usable config source and the section went out undeclared -- while
// authentication, KMS and audit logging live ONLY in the Helm values. The report
// therefore said the cluster had no dashboard authentication and no KMS, failed
// two Critical checks on it, and published a ransomware grade three bands lower.
// Reading a Secret in the Kasten namespace is the most likely denial in the plan.
func TestRefusedHelmReadDoesNotReportAnUnauthenticatedCluster(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{
			"configmaps": {k10ConfigMap(map[string]any{"logLevel": "info"})},
		},
		errs: map[string]error{"secrets": forbidden("secrets")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	if got := r.K10Configuration.Security.Authentication.Method; got != "unknown" {
		t.Errorf("auth method = %q, want unknown: the only source for it was refused", got)
	}
	for _, tc := range []struct{ name, got string }{
		{"authentication", r.BestPractices.Authentication},
		{"encryption", r.BestPractices.Encryption},
		{"auditLogging", r.BestPractices.AuditLogging},
	} {
		if tc.got != kdl.StatusNotAssessed {
			t.Errorf("bestPractices.%s = %q, want %q", tc.name, tc.got, kdl.StatusNotAssessed)
		}
	}
	if !r.NotCollected("k10Configuration") {
		t.Error("k10Configuration is not declared although the Helm read was refused")
	}
	if !r.NotCollected("ransomwareReadiness") {
		t.Error("the ransomware grade is published although four of its pillars read " +
			"security settings nobody could read")
	}

	// The ConfigMap did answer for the rest of the section, so those values are
	// real and must survive.
	if r.K10Configuration.LogLevel != "info" {
		t.Errorf("logLevel = %q, want the ConfigMap's value: it answered", r.K10Configuration.LogLevel)
	}
}

// TestStorageClassAccessibilityIsAClaimAboutTheRead: rbacAccessible was never
// assigned, so it said "denied" on every report and the renderer hid the classes
// it had collected behind an RBAC warning describing nothing that happened. The
// honesty mechanism inverted.
func TestStorageClassAccessibilityIsAClaimAboutTheRead(t *testing.T) {
	sc := obj("StorageClass", "fast", map[string]any{"provisioner": "csi.example.com"})
	ok := buildAt(t, map[string][]unstructured.Unstructured{"storageclasses": {sc}})

	if !ok.StorageClasses.RBACAccessible {
		t.Error("storageClasses.rbacAccessible = false after a successful read; the page then " +
			"claims an RBAC denial and hides the classes it collected")
	}
	if !ok.VolumeSnapshotClasses.RBACAccessible {
		t.Error("volumeSnapshotClasses.rbacAccessible = false after a successful read")
	}
	// And the page proves it: the collected class has to appear.
	if html := renderFor(t, ok); !strings.Contains(html, "csi.example.com") {
		t.Error("the rendered page does not mention the collected storage class")
	}

	denied := Build(collect(t, &fakeReader{errs: map[string]error{
		"storageclasses": forbidden("storageclasses"),
	}}))
	if denied.StorageClasses.RBACAccessible {
		t.Error("storageClasses.rbacAccessible = true although the read was refused")
	}
}

// TestDeniedExclusionReadDoesNotInventACoverageGap: the namespace-protection check
// reads the actionable gap count, so when the deliberate-exclusion breakdown is
// unknown the check is unanswerable. It used to fall back to the raw count -- the
// number the declaration invalidates -- turning COMPLETE into GAPS_DETECTED.
func TestDeniedExclusionReadDoesNotInventACoverageGap(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{
			"namespaces": {obj("Namespace", "opted-out", nil)},
			"policies": {policy("selective", map[string]any{
				"actions": []any{map[string]any{"action": "backup"}},
				"selector": map[string]any{"matchExpressions": []any{
					map[string]any{
						"key": "k10.kasten.io/appNamespace", "operator": "In",
						"values": []any{"nothing"},
					},
				}},
			})},
		},
		errs: map[string]error{"configmaps": forbidden("configmaps")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	if !r.NotCollected("coverage.unprotectedBreakdown") {
		t.Fatal("the exclusion breakdown is not declared although the ConfigMap read was refused")
	}
	if got := r.BestPractices.NamespaceProtection; got != kdl.StatusNotAssessed {
		t.Errorf("namespaceProtection = %q, want %q: whether the one unprotected namespace "+
			"was deliberately excluded is exactly what could not be read", got, kdl.StatusNotAssessed)
	}
}

// TestCatchallStillAnswersWithoutTheExclusionList is the positive control for the
// test above: a catch-all policy protects every application namespace, so no
// exclusion list can change the answer and the check must still be answered.
func TestCatchallStillAnswersWithoutTheExclusionList(t *testing.T) {
	res := collect(t, &fakeReader{
		lists: map[string][]unstructured.Unstructured{
			"namespaces": {obj("Namespace", "app-a", nil)},
			"policies": {policy("everything", map[string]any{
				"actions": []any{map[string]any{"action": "backup"}},
			})},
		},
		errs: map[string]error{"configmaps": forbidden("configmaps")},
	})
	res.CollectedAt = testNow

	if got := Build(res).BestPractices.NamespaceProtection; got != statusComplete {
		t.Errorf("namespaceProtection = %q, want %q: a catch-all policy needs no exclusion list",
			got, statusComplete)
	}
}

// TestDRStalenessMatchesTheShellBetweenWholeDays: KDL.sh compares raw seconds
// against seven days, and flooring to whole days first made a DR last successful
// 7.5 days ago read ENABLED where the shell says CONFIGURED_NOT_HEALTHY -- a
// critical check and 15 ransomware points, a whole grade band, in the reassuring
// direction.
func TestDRStalenessMatchesTheShellBetweenWholeDays(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{6 * 24 * time.Hour, drEnabled},
		{7 * 24 * time.Hour, drEnabled},
		{7*24*time.Hour + time.Minute, drNotHealthy},
		{180 * time.Hour, drNotHealthy}, // 7.5 days: the divergence
		{8 * 24 * time.Hour, drNotHealthy},
	} {
		r := buildAt(t, map[string][]unstructured.Unstructured{
			"policies":   {quickDR()},
			"runactions": {runAction("dr", drPolicyName, stateComplete, ago(tc.age), "", "")},
		})
		if got := r.DisasterRecovery.Status; got != tc.want {
			t.Errorf("last success %v ago: status = %q, want %q", tc.age, got, tc.want)
		}
	}
}

// renderFor renders a collected report, so a test can assert on what a customer
// actually sees rather than on the JSON alone.
func renderFor(t *testing.T, r *kdl.Report) string {
	t.Helper()
	var sb strings.Builder
	if err := report.Render(r, &sb, report.Options{}); err != nil {
		t.Fatalf("render: %v", err)
	}
	return sb.String()
}

// TestSubFieldsWithConsumersAreActuallyFilled: nine sub-fields had a renderer
// reading them and no builder writing them, so the page showed a count with no
// table, a "VMs at a time" row with no number, and a Restore History that was
// always empty. A section counted as populated while the rows a reader came for
// were missing.
func TestSubFieldsWithConsumersAreActuallyFilled(t *testing.T) {
	restore := func(name, appNS, state, created string) unstructured.Unstructured {
		return action("RestoreAction", name, appNS, "", state, created, nil)
	}
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "app-a", nil)},
		"policies": {policy("import-from-s3", map[string]any{
			"frequency": "@daily",
			"actions": []any{map[string]any{
				"action":           "import",
				"importParameters": map[string]any{"profile": map[string]any{"name": "s3-source"}},
			}},
		})},
		"restoreactions": {
			restore("r-old", "app-a", stateComplete, ago(48*time.Hour)),
			restore("r-new", "app-a", stateFailed, ago(time.Hour)),
		},
		"storageclasses": {
			obj("StorageClass", "fast", map[string]any{"provisioner": "ebs.csi.aws.com"}),
			obj("StorageClass", "legacy", map[string]any{"provisioner": "kubernetes.io/aws-ebs"}),
		},
		"volumesnapshotclasses": {
			obj("VolumeSnapshotClass", "csi-snap", map[string]any{"driver": "efs.csi.aws.com"}),
		},
		"blueprintbindings": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "pg-binding", "namespace": "kasten-io"},
			"spec":     map[string]any{"blueprint": "postgres-bp"},
		}}},
		"kubevirts": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "kubevirt", "namespace": "kubevirt"},
			"status":   map[string]any{"observedKubeVirtVersion": "v1.2.2"},
		}}},
		"virtualmachines": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "vm-1", "namespace": "app-a"},
			"status":   map[string]any{"printableStatus": "Running"},
		}}},
		"secrets": {helmRelease("v1", map[string]any{
			"limiter": map[string]any{"vmSnapshotsPerCluster": float64(4)},
		})},
	})

	if got := r.Health.Backups.RestoreActions.Recent; len(got) != 2 || got[0].Name != "r-new" {
		t.Errorf("recent restores = %+v, want both, newest first", got)
	} else if got[0].TargetNamespace != "app-a" {
		t.Errorf("recent restore namespace = %q, want app-a, resolved as in the failed list",
			got[0].TargetNamespace)
	}

	// ebs.csi.aws.com is a CSI provisioner with no matching snapshot class; the
	// in-tree one must not be reported, since it never uses CSI snapshots.
	missing := r.VolumeSnapshotClasses.CSIDriversWithoutVSC
	if missing.Count != 1 || len(missing.Drivers) != 1 || missing.Drivers[0] != "ebs.csi.aws.com" {
		t.Errorf("csiDriversWithoutVsc = %+v, want just ebs.csi.aws.com", missing)
	}

	if len(r.ImportPolicies.Items) != 1 || r.ImportPolicies.Items[0].Profile != "s3-source" {
		t.Errorf("import policy = %+v, want its profile resolved", r.ImportPolicies.Items)
	}
	if len(r.Kanister.Bindings.Items) != 1 || r.Kanister.Bindings.Items[0].Blueprint != "postgres-bp" {
		t.Errorf("kanister bindings = %+v, want the blueprint each one binds", r.Kanister.Bindings.Items)
	}
	if r.Virtualization.Version != "v1.2.2" {
		t.Errorf("virtualization version = %q, want v1.2.2 from the KubeVirt CR", r.Virtualization.Version)
	}
	if r.Virtualization.SnapshotConcurrency != "4" {
		t.Errorf("snapshotConcurrency = %q, want 4 from the limiter", r.Virtualization.SnapshotConcurrency)
	}
	if r.Virtualization.FreezeConfiguration.Timeout == "" {
		t.Error("freeze timeout is empty; the row renders with no value")
	}
	if len(r.PolicyAnalysis.Resolved) != 1 {
		t.Fatalf("policyAnalysis.resolved = %+v, want one entry per analysed policy",
			r.PolicyAnalysis.Resolved)
	}
}

// TestRBACInventoryListsAndNotJustCounts: an audit needs to know who has access
// through which role. Three of the four lists reported a count with no rows.
func TestRBACInventoryListsAndNotJustCounts(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"clusterrolebindings": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "k10-admin"},
			"roleRef":  map[string]any{"name": "k10-admin-role"},
			"subjects": []any{map[string]any{"kind": "User", "name": "alice@example.com"}},
		}}},
		"roles": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "k10-ns-role", "namespace": "kasten-io"},
			"rules":    []any{map[string]any{"verbs": []any{"get"}}},
		}}},
		"rolebindings": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "k10-ns-binding", "namespace": "kasten-io"},
			"roleRef":  map[string]any{"name": "k10-ns-role"},
			"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "k10-sa"}},
		}}},
	})

	crb := r.K10RBAC.ClusterRoleBindings
	if crb.Count != 1 || len(crb.Items) != 1 {
		t.Fatalf("clusterRoleBindings = %+v, want one entry, not just a count", crb)
	}
	if crb.Items[0].RoleRef != "k10-admin-role" || len(crb.Items[0].Subjects) != 1 {
		t.Errorf("binding = %+v, want its roleRef and subject", crb.Items[0])
	}
	if len(r.K10RBAC.Roles.Items) != 1 || r.K10RBAC.Roles.Items[0].RulesCount != 1 {
		t.Errorf("roles = %+v, want the rule count per role", r.K10RBAC.Roles.Items)
	}
	if len(r.K10RBAC.RoleBindings.Items) != 1 ||
		r.K10RBAC.RoleBindings.Items[0].RoleRef != "k10-ns-role" {
		t.Errorf("roleBindings = %+v, want each binding's roleRef", r.K10RBAC.RoleBindings.Items)
	}
}
