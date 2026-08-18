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
