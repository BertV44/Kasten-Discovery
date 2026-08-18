package scan

import (
	"testing"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// healthyCluster is the input a well-configured cluster produces: immutable
// profile, exporting policy, healthy DR, and a Helm release with the four
// security settings the pillars read.
func healthyCluster() map[string][]unstructured.Unstructured {
	return map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "app-a", nil)},
		"policies": {
			policy("daily", map[string]any{
				"frequency": "@daily",
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
			quickDR(),
		},
		"profiles": {unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "s3"},
			"spec": map[string]any{"locationSpec": map[string]any{
				"objectStore": map[string]any{"protectionPeriod": "720h"}}},
			"status": map[string]any{"validation": "Success"},
		}}},
		"runactions": {runAction("dr-1", drPolicyName, stateComplete, ago(time.Hour), "", "")},
		"secrets": {helmRelease("v1", map[string]any{
			"auth":          map[string]any{"tokenAuth": map[string]any{"enabled": true}},
			"encryption":    map[string]any{"primaryKey": map[string]any{"awsCmkKeyId": "arn:aws:kms:key/1"}},
			"siem":          map[string]any{"logging": map[string]any{"cluster": map[string]any{"enabled": true}}},
			"networkPolicy": map[string]any{"create": true},
		})},
	}
}

// TestRansomwareScoreIsTheSumOfItsPillars, and the pillars are all-or-nothing.
func TestRansomwareScoreIsTheSumOfItsPillars(t *testing.T) {
	r := buildAt(t, healthyCluster())
	rr := r.RansomwareReadiness

	if rr.MaxScore != 100 {
		t.Fatalf("maxScore = %d, want 100", rr.MaxScore)
	}
	// Everything but the DR pillar's dependants: immutability 20, export 15,
	// auth 15, DR 15, audit 10, KMS 10, netpol 10, TLS 5.
	if rr.Score != 100 {
		t.Errorf("score = %d, want 100 on a fully configured cluster: %+v", rr.Score, rr.Pillars)
	}
	if rr.Grade != "A" {
		t.Errorf("grade = %q, want A at 100 points", rr.Grade)
	}
	if r.NotCollected("ransomwareReadiness") {
		t.Error("ransomwareReadiness is declared unpopulated on a cluster where every input was read")
	}
}

// TestDRPillarPaysOnlyForAHealthyDR: a 15/15 next to a CONFIGURED_NOT_HEALTHY
// verdict is a contradiction a reader resolves in the reassuring direction, so
// the pillar follows the effective verdict rather than the policy's existence.
func TestDRPillarPaysOnlyForAHealthyDR(t *testing.T) {
	lists := healthyCluster()
	// The DR policy is still there; its last run now fails.
	lists["runactions"] = []unstructured.Unstructured{
		runAction("dr-1", drPolicyName, stateFailed, ago(time.Hour), "", ""),
	}
	r := buildAt(t, lists)

	if got := r.DisasterRecovery.Status; got != drNotHealthy {
		t.Fatalf("dr status = %q, want %q", got, drNotHealthy)
	}
	if p := r.RansomwareReadiness.Pillars.DisasterRecovery; p.Score != 0 || p.Evidence {
		t.Errorf("DR pillar = %+v, want 0 points and no evidence for an unhealthy DR", p)
	}
	if got := r.RansomwareReadiness.Score; got != 85 {
		t.Errorf("score = %d, want 85 (100 less the 15 DR points)", got)
	}
	if got := r.BestPractices.DisasterRecovery; got != drNotHealthy {
		t.Errorf("bestPractices.disasterRecovery = %q, want the DR verdict verbatim so the two cannot disagree", got)
	}
}

// TestBiggestGapNamesTheHeaviestUnscoredPillar: the grade tells a CISO where they
// stand, this tells an engineer what to do first.
func TestBiggestGapNamesTheHeaviestUnscoredPillar(t *testing.T) {
	lists := healthyCluster()
	// Drop immutability (20 points) and audit logging (10).
	lists["profiles"] = []unstructured.Unstructured{{Object: map[string]any{
		"metadata": map[string]any{"name": "s3"},
		"spec":     map[string]any{"locationSpec": map[string]any{"objectStore": map[string]any{}}},
	}}}
	lists["secrets"] = []unstructured.Unstructured{helmRelease("v1", map[string]any{
		"auth":          map[string]any{"tokenAuth": map[string]any{"enabled": true}},
		"encryption":    map[string]any{"primaryKey": map[string]any{"awsCmkKeyId": "arn:aws:kms:key/1"}},
		"networkPolicy": map[string]any{"create": true},
	})}

	r := buildAt(t, lists)
	gap := r.RansomwareReadiness.BiggestGap
	if gap.Pillar != "Immutability" || gap.PointsLost != 20 {
		t.Errorf("biggestGap = %+v, want Immutability at 20 points -- the heaviest unscored pillar", gap)
	}
}

// TestTLSPillarSeesAVBRProfile is the bug this deep scan exists for: KDL.sh
// looked only under locationSpec.objectStore and infrastoreBlobStore, so a Veeam
// Backup & Replication profile -- where the flag lives under locationSpec.vbr,
// and which Kasten 9.0 makes a first-class export target -- always reported TLS
// verification as enabled, handing a free 5/5 to clusters exporting over
// unverified TLS.
func TestTLSPillarSeesAVBRProfile(t *testing.T) {
	lists := healthyCluster()
	lists["profiles"] = append(lists["profiles"], unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "vbr-repo"},
		"spec": map[string]any{"locationSpec": map[string]any{
			"vbr": map[string]any{"repoName": "hardened-01", "skipSSLVerify": true}}},
	}})

	r := buildAt(t, lists)
	tls := r.RansomwareReadiness.Pillars.TLSVerification
	if tls.Score != 0 || tls.Evidence {
		t.Errorf("TLS pillar = %+v, want 0 points: a profile skips certificate verification", tls)
	}
	if len(tls.ProfilesSkippingTLS) != 1 || tls.ProfilesSkippingTLS[0].Name != "vbr-repo" {
		t.Errorf("profilesSkippingTls = %+v, want vbr-repo named", tls.ProfilesSkippingTLS)
	}
}

// TestUnreadInputIsNotAssessedRatherThanFailing is the whole reason these two
// sections were withheld. Leaving a check empty makes the renderer fail it, which
// paints the two critical checks "✗ CRITICAL" and the report banner "2 Critical"
// on a cluster where nobody looked at either.
func TestUnreadInputIsNotAssessedRatherThanFailing(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{})
	bp := r.BestPractices

	for _, tc := range []struct{ name, got string }{
		{"authentication", bp.Authentication},
		{"encryption", bp.Encryption},
		{"auditLogging", bp.AuditLogging},
	} {
		if tc.got != kdl.StatusNotAssessed {
			t.Errorf("%s = %q, want %q: no config source was readable",
				tc.name, tc.got, kdl.StatusNotAssessed)
		}
	}
	// And not the opposite error either: an unassessed check must not pass.
	for _, tc := range []struct{ name, got string }{
		{"authentication", bp.Authentication},
		{"encryption", bp.Encryption},
	} {
		if tc.got == statusConfigured || tc.got == statusEnabled || tc.got == statusOK {
			t.Errorf("%s = %q, which reads as a pass on a cluster nobody could inspect", tc.name, tc.got)
		}
	}
	// The section stays published: thirteen of the sixteen checks did get a real
	// verdict here, kdl diff already skips an individual NOT_ASSESSED, and
	// blanking the section would throw those thirteen away for nothing.
	if r.NotCollected("bestPractices") {
		t.Error("bestPractices is declared unpopulated although most of its checks were assessed")
	}
	// The grade cannot degrade that way: it is one number, and a pillar scored
	// zero for lack of evidence reads as a failed control.
	if !r.NotCollected("ransomwareReadiness") {
		t.Error("ransomwareReadiness is not declared unpopulated; a grade has no room for 'partly unknown'")
	}
}

// TestBestPracticesIsDeclaredOnlyWhenNothingWasAssessed: a section where no check
// could be evaluated says nothing about the cluster, and that is the one case
// where publishing it is worse than declaring it.
func TestBestPracticesIsDeclaredOnlyWhenNothingWasAssessed(t *testing.T) {
	denied := map[string]error{}
	for _, resource := range []string{
		"policies", "runactions", "namespaces", "profiles", "pods", "deployments",
		"policypresets", "virtualmachines", "restorepoints", "secrets", "configmaps",
	} {
		denied[resource] = forbidden(resource)
	}
	res := collect(t, &fakeReader{errs: denied})
	res.CollectedAt = testNow
	r := Build(res)

	if !r.NotCollected("bestPractices") {
		t.Errorf("bestPractices is not declared with every input denied: %+v", r.BestPractices)
	}
	if bestPracticesAnyAssessed(r) {
		t.Errorf("a check reports a verdict with every input denied: %+v", r.BestPractices)
	}
}

// TestDeniedPolicyReadDoesNotFailTheRetentionChecks: three checks read the
// retention analysis, and a denied policy listing must not make them all pass or
// all fail.
func TestDeniedPolicyReadDoesNotFailTheRetentionChecks(t *testing.T) {
	res := collect(t, &fakeReader{errs: map[string]error{"policies": forbidden("policies")}})
	res.CollectedAt = testNow
	r := Build(res)
	bp := r.BestPractices

	for _, tc := range []struct{ name, got string }{
		{"snapshotRetentionHigh", bp.SnapshotRetentionHigh},
		{"snapshotRetentionZero", bp.SnapshotRetentionZero},
		{"exportRetentionExplicit", bp.ExportRetentionExplicit},
		{"clusterScopedResources", bp.ClusterScopedResources},
		{"policiesWithoutExport", bp.PoliciesWithoutExport},
		{"namespaceProtection", bp.NamespaceProtection},
	} {
		if tc.got != kdl.StatusNotAssessed {
			t.Errorf("%s = %q, want %q with the policy listing denied", tc.name, tc.got, kdl.StatusNotAssessed)
		}
	}
}

// TestNamespaceProtectionUsesTheActionableCount: a namespace deliberately
// excluded is not a gap, and counting it as one buries the ones that are.
func TestNamespaceProtectionUsesTheActionableCount(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "opted-out", nil), obj("Namespace", "covered", nil)},
		"policies": {policy("selective", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchExpressions": []any{
				map[string]any{
					"key":      "k10.kasten.io/appNamespace",
					"operator": "In",
					"values":   []any{"covered"},
				},
			}},
		})},
		"secrets": {helmRelease("v1", map[string]any{
			"excludedApps": []any{"opted-out"},
		})},
	})

	if got := r.Coverage.UnprotectedNamespaces.Count; got != 1 {
		t.Fatalf("raw unprotected = %d, want 1 (opted-out): the raw figure is untouched", got)
	}
	if got := r.BestPractices.NamespaceProtection; got != statusComplete {
		t.Errorf("namespaceProtection = %q, want %q: the only gap is a namespace somebody opted out of",
			got, statusComplete)
	}
}

// TestVMChecksAreNotApplicableWithoutVMs: an inapplicable check must read as
// inapplicable, not as a pass.
func TestVMChecksAreNotApplicableWithoutVMs(t *testing.T) {
	r := buildAt(t, healthyCluster())
	if got := r.BestPractices.VMProtection; got != statusNA {
		t.Errorf("vmProtection = %q, want %q on a cluster with no VMs", got, statusNA)
	}
	if got := r.BestPractices.VMSnapshotConsistency; got != statusNA {
		t.Errorf("vmSnapshotConsistency = %q, want %q", got, statusNA)
	}
}

// TestVMProtectionGradesRealCoverage, and distinguishes a VM protected as a VM
// from one caught incidentally by its namespace's policy.
func TestVMProtectionGradesRealCoverage(t *testing.T) {
	vm := func(name, ns string, labels map[string]any) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachine",
			"metadata":   map[string]any{"name": name, "namespace": ns, "labels": labels},
			"status":     map[string]any{"printableStatus": "Running", "ready": true},
		}}
	}

	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "vms", nil), obj("Namespace", "other", nil)},
		"virtualmachines": {
			vm("db", "vms", map[string]any{"tier": "gold"}),
			vm("web", "vms", map[string]any{"tier": "bronze"}),
			vm("orphan", "other", nil),
		},
		"policies": {
			// A 9.0 label-based VM policy: the namespace selects, then matchLabels
			// filters VMs -- not namespaces.
			policy("gold-vms", map[string]any{
				"frequency": "@daily",
				"actions":   []any{map[string]any{"action": "backup"}},
				"selector": map[string]any{
					"matchExpressions": []any{map[string]any{
						"key":      "k10.kasten.io/virtualMachineNamespace",
						"operator": "In",
						"values":   []any{"vms"},
					}},
					"matchLabels": map[string]any{"tier": "gold"},
				},
			}),
		},
	})

	p := r.Virtualization.Protection
	if p.ProtectedVMs != 1 || p.UnprotectedVMs != 2 {
		t.Fatalf("protection = %+v, want 1 protected and 2 unprotected: matchLabels filters VMs, "+
			"so only the gold VM is covered -- not the whole namespace", p)
	}
	if len(p.UnprotectedVMList) != 2 || !contains(p.UnprotectedVMList, "vms/web") {
		t.Errorf("unprotectedVmList = %v, want vms/web among them", p.UnprotectedVMList)
	}
	if got := r.BestPractices.VMProtection; got != statusPartial {
		t.Errorf("vmProtection = %q, want %q with some VMs covered and some not", got, statusPartial)
	}
	if r.Virtualization.VMPolicies.Count != 1 {
		t.Errorf("vmPolicies = %d, want 1", r.Virtualization.VMPolicies.Count)
	}
	if bl := r.Virtualization.VMPolicies.ByLabelSelector; bl == nil || *bl != 1 {
		t.Errorf("byLabelSelector = %v, want 1", bl)
	}
}

// TestNamespacePolicyCoversItsVMs: a VM whose namespace is selected does get its
// PVCs backed up, so it counts as protected -- but reported separately, because a
// namespace policy does not quiesce the guest.
func TestNamespacePolicyCoversItsVMs(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "vms", nil)},
		"virtualmachines": {unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "kubevirt.io/v1",
			"kind":       "VirtualMachine",
			"metadata":   map[string]any{"name": "db", "namespace": "vms"},
			"status":     map[string]any{"printableStatus": "Running"},
		}}},
		"policies": {policy("everything", map[string]any{
			"frequency": "@daily",
			"actions":   []any{map[string]any{"action": "backup"}},
		})},
	})

	p := r.Virtualization.Protection
	if p.ProtectedVMs != 1 || p.CoveredByNamespacePolicies != 1 {
		t.Errorf("protection = %+v, want the VM covered by a namespace policy", p)
	}
	if cv := p.CoveredByVMPolicies; cv == nil || *cv != 0 {
		t.Errorf("coveredByVmPolicies = %v, want 0: no VM-scoped policy exists", cv)
	}
	if got := r.Virtualization.VMs[0].ProtectionSource; got != "namespacePolicy" {
		t.Errorf("protectionSource = %q, want namespacePolicy", got)
	}
	if got := r.BestPractices.VMProtection; got != statusComplete {
		t.Errorf("vmProtection = %q, want %q: every VM is covered", got, statusComplete)
	}
}

// TestDeniedVMReadIsNotNoVMs: a denied VM listing also leaves totalVMs at zero,
// so answering "N/A — no VMs on this cluster" first would make a refused read
// look like a fact about virtualization.
func TestDeniedVMReadIsNotNoVMs(t *testing.T) {
	res := collect(t, &fakeReader{
		errs: map[string]error{"virtualmachines": forbidden("virtualmachines")},
	})
	res.CollectedAt = testNow
	r := Build(res)

	if got := r.BestPractices.VMProtection; got != kdl.StatusNotAssessed {
		t.Errorf("vmProtection = %q, want %q: the VM listing was denied, not empty",
			got, kdl.StatusNotAssessed)
	}

	// And a cluster that genuinely serves no KubeVirt still reports N/A.
	served := map[string]bool{}
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		served[tg.gvr.Resource] = true
	}
	served["virtualmachines"] = false
	absent := collect(t, &fakeReader{served: served})
	absent.CollectedAt = testNow

	if got := Build(absent).BestPractices.VMProtection; got != statusNA {
		t.Errorf("vmProtection = %q, want %q on a cluster with no KubeVirt", got, statusNA)
	}
}

// TestTLSPillarIsNotFooledByAShallowFalse: a profile can carry the flag twice --
// false on one endpoint, true on another -- and taking the shallowest occurrence
// reported it as verifying TLS. That is KDL.sh's 2.2.0 bug reintroduced one level
// down, and it hands a free 5/5 to a cluster exporting over unverified TLS.
func TestTLSPillarIsNotFooledByAShallowFalse(t *testing.T) {
	lists := healthyCluster()
	lists["profiles"] = append(lists["profiles"], unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "mixed-endpoints"},
		"spec": map[string]any{"locationSpec": map[string]any{
			// Sorted first, so any "shallowest wins" rule resolves here.
			"objectStore": map[string]any{"skipSSLVerify": false},
			"vbr":         map[string]any{"repoName": "hardened-01", "skipSSLVerify": true},
		}},
	}})

	r := buildAt(t, lists)
	tls := r.RansomwareReadiness.Pillars.TLSVerification
	if tls.Score != 0 {
		t.Errorf("TLS pillar = %+v, want 0: one endpoint of the profile skips verification", tls)
	}
	if len(tls.ProfilesSkippingTLS) != 1 || tls.ProfilesSkippingTLS[0].Name != "mixed-endpoints" {
		t.Errorf("profilesSkippingTls = %+v, want mixed-endpoints named", tls.ProfilesSkippingTLS)
	}
}

// TestTLSPillarPassesWhenEveryFlagIsFalse is the positive control: without it the
// fix above could pass by flagging every profile.
func TestTLSPillarPassesWhenEveryFlagIsFalse(t *testing.T) {
	lists := healthyCluster()
	lists["profiles"] = append(lists["profiles"], unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "all-verified"},
		"spec": map[string]any{"locationSpec": map[string]any{
			"objectStore": map[string]any{"skipSSLVerify": false},
			"vbr":         map[string]any{"skipCertVerification": false},
		}},
	}})

	r := buildAt(t, lists)
	tls := r.RansomwareReadiness.Pillars.TLSVerification
	if tls.Score != pillarTLSVerificationMax || !tls.Evidence {
		t.Errorf("TLS pillar = %+v, want the full %d: every flag is false",
			tls, pillarTLSVerificationMax)
	}
	if len(tls.ProfilesSkippingTLS) != 0 {
		t.Errorf("profilesSkippingTls = %+v, want empty", tls.ProfilesSkippingTLS)
	}
}
