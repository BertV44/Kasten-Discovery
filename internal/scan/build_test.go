package scan

import (
	"strings"
	"testing"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// policy builds a policy object shaped like the CRD KDL.sh reads.
func policy(name string, spec map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "config.kio.kasten.io/v1alpha1",
		"kind":       "Policy",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}
}

func buildFrom(t *testing.T, lists map[string][]unstructured.Unstructured) *kdl.Report {
	t.Helper()
	return Build(collect(t, &fakeReader{lists: lists}))
}

// TestDualExportPolicyKeepsBothDestinations: since Kasten 9.0 a policy can
// carry two export actions, each with its own profile. Reading "the" export of
// a policy silently drops the second destination.
func TestDualExportPolicyKeepsBothDestinations(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("dual", map[string]any{
			"frequency": "@daily",
			"actions": []any{
				map[string]any{"action": "backup"},
				map[string]any{"action": "export", "exportParameters": map[string]any{
					"profile": map[string]any{"name": "s3-primary"}}},
				map[string]any{"action": "export", "exportParameters": map[string]any{
					"profile": map[string]any{"name": "vbr-secondary"}}},
			},
		})},
	})

	if len(r.Policies.Items) != 1 {
		t.Fatalf("policies = %d, want 1", len(r.Policies.Items))
	}
	p := r.Policies.Items[0]
	if len(p.Exports) != 2 {
		t.Fatalf("exports = %d, want 2: a Kasten 9.0 additional export was dropped", len(p.Exports))
	}
	got := []string{deref(p.Exports[0].Profile), deref(p.Exports[1].Profile)}
	for _, want := range []string{"s3-primary", "vbr-secondary"} {
		if !contains(got, want) {
			t.Errorf("exports = %v, want %q among them", got, want)
		}
	}
	if r.Policies.AdditionalExport == nil || r.Policies.AdditionalExport.Count != 1 {
		t.Error("a dual-export policy was not counted in additionalExport")
	}
}

// TestPolicyWithoutExportStillAppears: a jq generator bug once dropped
// export-less policies from the list entirely, producing a count that
// disagreed with items. The Go collector must not reintroduce it.
func TestPolicyWithoutExportStillAppears(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {
			policy("snap-only", map[string]any{"actions": []any{map[string]any{"action": "backup"}}}),
			policy("with-export", map[string]any{"actions": []any{
				map[string]any{"action": "backup"},
				map[string]any{"action": "export", "exportParameters": map[string]any{
					"profile": map[string]any{"name": "s3"}}},
			}}),
		},
	})

	if r.Policies.Count != len(r.Policies.Items) {
		t.Errorf("count = %d but items holds %d", r.Policies.Count, len(r.Policies.Items))
	}
	if r.Policies.Count != 2 {
		t.Fatalf("policies = %d, want 2", r.Policies.Count)
	}
	if r.Policies.WithExport != 1 {
		t.Errorf("withExport = %d, want 1", r.Policies.WithExport)
	}
}

// TestVMRefSelectorIsNotReducedToItsNamespace: a policy protecting one VM must
// not become indistinguishable from one protecting the whole namespace.
func TestVMRefSelectorIsNotReducedToItsNamespace(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("one-vm", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchExpressions": []any{
				map[string]any{
					"key":      "k10.kasten.io/virtualMachineRef",
					"operator": "In",
					"values":   []any{"vm-ns-1/fedora-87"},
				}}},
		})},
	})

	p := r.Policies.Items[0]
	if p.Scope != kdl.ScopeVirtualMachine {
		t.Errorf("scope = %q, want %q", p.Scope, kdl.ScopeVirtualMachine)
	}
	targets := p.Selector.TargetPatterns()
	if !contains(targets, "vm-ns-1/fedora-87") {
		t.Errorf("targets = %v, want the full VM reference kept", targets)
	}
}

// TestUnmodelledSelectorIsNotACatchAll: a selector shape this build does not
// understand must read as "scope unknown", never as "protects everything".
// Downgrading it to a catch-all would report unprotected workloads as covered.
func TestUnmodelledSelectorIsNotACatchAll(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("weird", map[string]any{
			"actions":  []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"someFutureKasten10Key": "value"},
		})},
	})

	p := r.Policies.Items[0]
	if p.Selector.All {
		t.Error("an unmodelled selector was treated as a catch-all: it would claim to protect everything")
	}
	if !p.Selector.Unrecognized() {
		t.Error("an unmodelled selector must report Unrecognized() so callers can say 'scope unknown'")
	}
}

// TestPresetScheduledPolicyKeepsItsPresetRef: the preset is what schedules such
// a policy, and both the report and the renderer need it to avoid calling the
// policy manual.
func TestPresetScheduledPolicyKeepsItsPresetRef(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("by-preset", map[string]any{
			"actions":   []any{map[string]any{"action": "backup"}},
			"presetRef": map[string]any{"name": "kubecon-daily"},
		})},
	})

	p := r.Policies.Items[0]
	if p.Frequency != nil {
		t.Errorf("frequency = %q, want nil: the policy declares none of its own", *p.Frequency)
	}
	if p.PresetRef == nil || *p.PresetRef != "kubecon-daily" {
		t.Error("presetRef was dropped; the renderer would then call the policy manual")
	}
	if r.Policies.WithPresets != 1 {
		t.Errorf("withPresets = %d, want 1", r.Policies.WithPresets)
	}
}

// TestHourlyRetentionIsRead: hourly is a valid Kasten tier that no sample in
// this repository exercises, so it is exactly the one a collector forgets.
func TestHourlyRetentionIsRead(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("hourly-pol", map[string]any{
			"actions":   []any{map[string]any{"action": "backup"}},
			"retention": map[string]any{"hourly": int64(24), "daily": int64(7)},
		})},
	})

	got := r.Policies.Items[0].Retention
	if got.Hourly != 24 {
		t.Errorf("hourly retention = %d, want 24", got.Hourly)
	}
	if got.Daily != 7 {
		t.Errorf("daily retention = %d, want 7", got.Daily)
	}
}

// TestProfileFieldsSurviveDeeperNesting is the point of the bounded deep scan.
// KDL.sh resolves these fields that way because "the exact nesting differs
// between the documented schema and what live clusters return"; a fixed path
// would silently miss them on exactly the clusters worth reporting on.
func TestProfileFieldsSurviveDeeperNesting(t *testing.T) {
	nested := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "deep-profile"},
		"spec": map[string]any{
			"locationSpec": map[string]any{
				"credential": map[string]any{"secret": map[string]any{"name": "s"}},
				"objectStore": map[string]any{
					"objectStoreType":  "S3",
					"region":           "eu-west-1",
					"endpoint":         "https://s3.example.com",
					"protectionPeriod": int64(2592000),
				},
			},
		},
	}}

	r := buildFrom(t, map[string][]unstructured.Unstructured{"profiles": {nested}})

	if len(r.Profiles.Items) != 1 {
		t.Fatalf("profiles = %d, want 1", len(r.Profiles.Items))
	}
	p := r.Profiles.Items[0]
	if p.Backend != "S3" {
		t.Errorf("backend = %q, want S3 found by the deep scan", p.Backend)
	}
	if p.Region != "eu-west-1" {
		t.Errorf("region = %q, want eu-west-1", p.Region)
	}
	if r.Profiles.ImmutableCount != 1 {
		t.Errorf("immutableCount = %d, want 1: a nested protectionPeriod was missed", r.Profiles.ImmutableCount)
	}
}

// TestHardenedVBRRepoCountsAsImmutable: a hardened VBR repository carries
// immutability that no protectionPeriod field reflects, so counting only
// protectionPeriod would report a genuinely immutable target as mutable.
func TestHardenedVBRRepoCountsAsImmutable(t *testing.T) {
	vbr := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "vbr-profile"},
		"spec": map[string]any{"locationSpec": map[string]any{
			"locationType": "VBR",
			"repoName":     "hardened-repo-1",
			"repoType":     "LinuxHardened",
		}},
	}}

	r := buildFrom(t, map[string][]unstructured.Unstructured{"profiles": {vbr}})

	if r.Profiles.VBRHardenedCount == nil || *r.Profiles.VBRHardenedCount != 1 {
		t.Error("a LinuxHardened VBR repository was not counted as hardened")
	}
	if !r.ImmutabilitySignal {
		t.Error("immutabilitySignal is false despite a hardened VBR repository")
	}
}

// TestSuccessRateOverZeroSamplesIsNotPerfect: a rate computed over nothing is
// not 100%. Emitting a perfect score for a cluster that has never run a backup
// is the misleading zero in its most dangerous form.
func TestSuccessRateOverZeroSamplesIsNotPerfect(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{})

	if got := r.Health.Backups.SuccessRate; got != "N/A" {
		t.Errorf("successRate = %q, want N/A when no action has finished", got)
	}
}

// TestSuccessRateExcludesRestores mirrors KDL.sh: a restore is an operator
// action, and folding restore failures into backup health hides a backup
// problem behind an unrelated one.
func TestSuccessRateExcludesRestores(t *testing.T) {
	action := func(state string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "a-" + state},
			"status":   map[string]any{"state": state},
		}}
	}
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"backupactions":  {action("Complete"), action("Complete")},
		"restoreactions": {action("Failed"), action("Failed"), action("Failed")},
	})

	if got := r.Health.Backups.SuccessRate; got != "100.0" {
		t.Errorf("successRate = %q, want 100.0: three failed restores must not drag down backup health", got)
	}
	if r.Health.Backups.RestoreActions.Failed != 3 {
		t.Errorf("restore failures = %d, want them still reported separately", r.Health.Backups.RestoreActions.Failed)
	}
}

// TestActionStatesAreDisjoint: total must equal the sum of its parts, or a
// reader adding up the columns finds them short.
func TestActionStatesAreDisjoint(t *testing.T) {
	action := func(name, state string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": name},
			"status":   map[string]any{"state": state},
		}}
	}
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"restoreactions": {
			action("a", "Complete"), action("b", "Failed"),
			action("c", "Running"), action("d", "Pending"),
		},
	})

	ra := r.Health.Backups.RestoreActions
	if sum := ra.Completed + ra.Failed + ra.Running + ra.Other; sum != ra.Total {
		t.Errorf("completed+failed+running+other = %d but total = %d", sum, ra.Total)
	}
}

// TestSystemPoliciesAreExcludedFromCoverage: judging a customer's posture on
// Kasten's own housekeeping policies would credit them for protection they did
// not configure.
func TestSystemPoliciesAreExcludedFromCoverage(t *testing.T) {
	catchAll := map[string]any{"actions": []any{map[string]any{"action": "backup"}}}
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies":   {policy("k10-disaster-recovery-policy", catchAll)},
		"namespaces": {obj("Namespace", "app-a", nil)},
	})

	if r.Coverage.HasCatchallPolicy {
		t.Error("a K10 system policy was counted as a customer catch-all")
	}
	if r.Coverage.UnprotectedNamespaces.Count != 1 {
		t.Errorf("unprotected = %d, want 1: app-a is not protected by a system policy",
			r.Coverage.UnprotectedNamespaces.Count)
	}
}

// TestExcludedNamespaceIsNotCountedProtected: the catch-all-with-exceptions
// shape is `appNamespace In ["*"]` plus a NotIn. Expanding the "*" without
// honouring the NotIn marks deliberately excluded namespaces as protected.
func TestExcludedNamespaceIsNotCountedProtected(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("almost-all", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchExpressions": []any{
				map[string]any{"key": "k10.kasten.io/appNamespace", "operator": "In", "values": []any{"*"}},
				map[string]any{"key": "k10.kasten.io/appNamespace", "operator": "NotIn", "values": []any{"excluded-ns"}},
			}},
		})},
		"namespaces": {obj("Namespace", "app-a", nil), obj("Namespace", "excluded-ns", nil)},
	})

	items := r.Coverage.UnprotectedNamespaces.Items
	if !contains(items, "excluded-ns") {
		t.Errorf("unprotected = %v, want excluded-ns among them: the NotIn was not honoured", items)
	}
	if contains(items, "app-a") {
		t.Errorf("unprotected = %v, want app-a protected by the wildcard", items)
	}
}

// TestUnpopulatedSectionsIsHonest guards the one thing a user comparing this
// against a KDL.sh report depends on: knowing which empty sections are "nothing
// found" and which are "not implemented".
func TestUnpopulatedSectionsIsHonest(t *testing.T) {
	listed := UnpopulatedSections()
	if len(listed) == 0 {
		t.Fatal("UnpopulatedSections is empty; the collector does not yet fill every section")
	}
	r := buildFrom(t, map[string][]unstructured.Unstructured{})
	// A section claimed as populated must not be in the not-implemented list.
	for _, s := range listed {
		if s == "policies" || s == "profiles" || s == "coverage" || s == "policyAnalysis" {
			t.Errorf("%q is listed as unpopulated but the collector does fill it", s)
		}
	}
	if r.KDLVersion != ScanVersion {
		t.Errorf("kdlVersion = %q, want %q so a Go-collected report is identifiable", r.KDLVersion, ScanVersion)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func contains(v []string, want string) bool {
	for _, s := range v {
		if s == want || strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// TestPlatformIsUnknownWhenUndetermined: "Kubernetes" is a claim, not a
// default. When the reads that would distinguish the platforms were denied or
// failed, saying Kubernetes prints a fact nobody established onto every page of
// the report.
func TestPlatformIsUnknownWhenUndetermined(t *testing.T) {
	r := Build(collect(t, &fakeReader{
		errs: map[string]error{
			"securitycontextconstraints": forbidden("securitycontextconstraints"),
			"routes":                     forbidden("routes"),
		},
	}))

	if r.Platform != "unknown" {
		t.Errorf("platform = %q, want unknown: neither OpenShift read resolved", r.Platform)
	}
}

// TestOpenShiftDetectedFromServedAPIsNotFromObjects: an OpenShift cluster with
// zero routes is still OpenShift. Requiring objects would misreport a fresh
// install as plain Kubernetes.
func TestOpenShiftDetectedFromServedAPIs(t *testing.T) {
	r := Build(collect(t, &fakeReader{lists: map[string][]unstructured.Unstructured{}}))

	if r.Platform != "OpenShift" {
		t.Errorf("platform = %q, want OpenShift: the cluster serves the OpenShift API groups even with no objects", r.Platform)
	}
}

// TestPlainKubernetesIsDetected is the counterpart: a cluster that serves
// neither OpenShift group is plain Kubernetes, and that is a resolved answer,
// not an unknown.
func TestPlainKubernetesIsDetected(t *testing.T) {
	f := &fakeReader{served: map[string]bool{}}
	for _, tg := range targets("kasten-io") {
		f.served[tg.gvr.Resource] = true
	}
	f.served["securitycontextconstraints"] = false
	f.served["routes"] = false

	if r := Build(collect(t, f)); r.Platform != "Kubernetes" {
		t.Errorf("platform = %q, want Kubernetes", r.Platform)
	}
}

// TestBlueprintActionsFoundUnderEitherShape: Kanister puts actions at the root,
// some blueprints nest them under spec. KDL.sh reads both, so reading only one
// would report half the blueprints as having no actions at all.
func TestBlueprintActionsFoundUnderEitherShape(t *testing.T) {
	root := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "root-shape", "namespace": "kasten-io"},
		"actions": map[string]any{
			"backup": map[string]any{}, "restore": map[string]any{},
		},
	}}
	nested := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "nested-shape", "namespace": "kasten-io"},
		"spec": map[string]any{"actions": map[string]any{
			"backup": map[string]any{}, "delete": map[string]any{},
		}},
	}}

	r := buildFrom(t, map[string][]unstructured.Unstructured{"blueprints": {root, nested}})

	if len(r.Kanister.Blueprints.Items) != 2 {
		t.Fatalf("blueprints = %d, want 2", len(r.Kanister.Blueprints.Items))
	}
	for _, bp := range r.Kanister.Blueprints.Items {
		if len(bp.Actions) != 2 {
			t.Errorf("blueprint %q has %d actions, want 2: the other shape was not read",
				bp.Name, len(bp.Actions))
		}
	}
}

// TestCompatibilityComparesVersionsNumerically: string comparison puts "9.10"
// before "9.2", which would report a newer Kasten as older and suppress exactly
// the warning a reader needs.
func TestCompatibilityComparesVersionsNumerically(t *testing.T) {
	for _, tc := range []struct {
		got  string
		want bool
	}{
		{"8.5", false}, {"9.0", false}, {"9.1", true}, {"9.10", true}, {"10.0", true},
	} {
		if got := newerThan(tc.got, KastenValidatedUpTo); got != tc.want {
			t.Errorf("newerThan(%q, %q) = %t, want %t", tc.got, KastenValidatedUpTo, got, tc.want)
		}
	}
}

// TestUnparseableKastenVersionIsNotOld: a version this build cannot parse is
// unknown, not old. Claiming "not newer than validated" would suppress the
// warning precisely when the version string changed shape.
func TestUnparseableKastenVersionIsNotOld(t *testing.T) {
	for _, v := range []string{"", "unknown", "digest-based", "sha256:abc"} {
		if _, ok := majorMinor(v); ok {
			t.Errorf("majorMinor(%q) claimed success on an unparseable version", v)
		}
	}
	r := buildFrom(t, map[string][]unstructured.Unstructured{})
	if r.KastenCompatibility == nil {
		t.Fatal("the compatibility block is absent from a report claiming to be 2.2.0-era")
	}
	if r.KastenCompatibility.DetectedMajorMinor != nil {
		t.Error("an unparseable version must leave detectedMajorMinor nil, not guess one")
	}
}

// TestKastenVersionReadFromCatalogLabel mirrors KDL.sh, which reads the version
// off the catalog deployment's app.kubernetes.io/version label.
func TestKastenVersionReadFromCatalogLabel(t *testing.T) {
	dep := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{
			"name":      "catalog-svc",
			"namespace": "kasten-io",
			"labels": map[string]any{
				"component":                 "catalog",
				"app.kubernetes.io/version": "9.0.3",
			},
		},
	}}

	r := buildFrom(t, map[string][]unstructured.Unstructured{"deployments": {dep}})

	if r.KastenVersion != "9.0.3" {
		t.Fatalf("kastenVersion = %q, want 9.0.3", r.KastenVersion)
	}
	if r.KastenCompatibility.DetectedMajorMinor == nil || *r.KastenCompatibility.DetectedMajorMinor != "9.0" {
		t.Error("detectedMajorMinor was not derived from the version")
	}
	if r.KastenCompatibility.NewerThanValidated {
		t.Error("9.0 is the validated ceiling and must not be flagged as newer")
	}
}

// TestEmptySelectorProtectsEverything: KDL.sh guards three degenerate selector
// shapes in three separate places, which is how live clusters really look. A
// cluster whose only catch-all backup policy carries an explicit empty selector
// was being reported as ENTIRELY UNPROTECTED -- the most alarming possible way
// to render a policy that in fact protects everything.
// A selector that states NO dimension is a catch-all. One that states a
// dimension and leaves it empty selects nothing, and must not be confused with
// it: claiming a policy that selects nothing protects everything drives
// unprotectedNamespaces to zero, which is the more dangerous of the two errors
// for a backup-posture tool.
func TestEmptySelectorProtectsEverything(t *testing.T) {
	cases := []struct {
		name     string
		selector any
		catchAll bool
	}{
		{"absent", nil, true},
		{"empty object", map[string]any{}, true},
		{"all keys null", map[string]any{"matchExpressions": nil, "matchNames": nil, "matchLabels": nil}, true},

		// States a dimension, matches nothing: an empty policy, not a catch-all.
		{"empty matchNames", map[string]any{"matchNames": []any{}}, false},
		{"empty matchExpressions", map[string]any{"matchExpressions": []any{}}, false},
		{"empty matchLabels", map[string]any{"matchLabels": map[string]any{}}, false},
		{"all keys present but empty", map[string]any{
			"matchExpressions": []any{}, "matchNames": []any{}, "matchLabels": map[string]any{},
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := map[string]any{"actions": []any{map[string]any{"action": "backup"}}}
			if tc.selector != nil {
				spec["selector"] = tc.selector
			}
			r := buildFrom(t, map[string][]unstructured.Unstructured{
				"policies":   {policy("p", spec)},
				"namespaces": {obj("Namespace", "app-a", nil), obj("Namespace", "app-b", nil)},
			})

			if got := r.Coverage.HasCatchallPolicy; got != tc.catchAll {
				t.Errorf("hasCatchallPolicy = %t, want %t", got, tc.catchAll)
			}
			wantUnprotected := 2
			if tc.catchAll {
				wantUnprotected = 0
			}
			if n := r.Coverage.UnprotectedNamespaces.Count; n != wantUnprotected {
				t.Errorf("unprotected = %d (%v), want %d",
					n, r.Coverage.UnprotectedNamespaces.Items, wantUnprotected)
			}
		})
	}
}

// TestNamespaceMatchLabelsAreResolved: a namespace-scoped policy selecting by
// namespace label marked nothing protected, so those namespaces were reported
// as gaps. KDL.sh fixed exactly this and labelled it a false-positive gap.
func TestNamespaceMatchLabelsAreResolved(t *testing.T) {
	prod := obj("Namespace", "app-prod", nil)
	prod.SetLabels(map[string]string{"tier": "prod"})
	dev := obj("Namespace", "app-dev", nil)
	dev.SetLabels(map[string]string{"tier": "dev"})

	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("by-label", map[string]any{
			"actions":  []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchLabels": map[string]any{"tier": "prod"}},
		})},
		"namespaces": {prod, dev},
	})

	items := r.Coverage.UnprotectedNamespaces.Items
	if contains(items, "app-prod") {
		t.Errorf("unprotected = %v, want app-prod protected by its namespace label", items)
	}
	if !contains(items, "app-dev") {
		t.Errorf("unprotected = %v, want app-dev reported: no policy selects it", items)
	}
}

// TestVMScopedMatchLabelsAreNotNamespaceLabels: on a VM policy, matchLabels
// filters VMs. Resolving it against the namespace inventory would credit a
// whole namespace to a policy protecting a handful of VMs inside it -- the
// confusion this codebase is structured to prevent.
func TestVMScopedMatchLabelsAreNotNamespaceLabels(t *testing.T) {
	ns := obj("Namespace", "vm-ns", nil)
	ns.SetLabels(map[string]string{"tier": "prod"})

	r := buildFrom(t, map[string][]unstructured.Unstructured{
		"policies": {policy("vm-by-label", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{
				"matchExpressions": []any{map[string]any{
					"key": "k10.kasten.io/virtualMachineNamespace", "operator": "In", "values": []any{"vm-ns"},
				}},
				"matchLabels": map[string]any{"tier": "prod"},
			},
		})},
		"namespaces": {ns, obj("Namespace", "app-other", nil)},
	})

	if r.Policies.Items[0].Scope != kdl.ScopeVirtualMachine {
		t.Fatalf("scope = %q, want virtualMachine", r.Policies.Items[0].Scope)
	}
	// app-other carries no matching label and no selector targets it either way.
	if !contains(r.Coverage.UnprotectedNamespaces.Items, "app-other") {
		t.Errorf("unprotected = %v, want app-other among them", r.Coverage.UnprotectedNamespaces.Items)
	}
}

// TestSystemNamespacesMatchTheShellPatterns: an earlier version carried three
// prefixes and a comment claiming it mirrored KDL.sh. It did not, and every
// platform component became a false coverage gap.
func TestSystemNamespacesMatchTheShellPatterns(t *testing.T) {
	system := []string{
		"kube-system", "openshift-monitoring", "kasten-io", "default",
		"argocd", "cert-manager", "istio-system", "velero", "prometheus",
		"grafana", "rook-ceph", "cattle-system", "vault", "monitoring", "logging",
	}
	for _, ns := range system {
		if !isSystemNamespace(ns) {
			t.Errorf("%q is a platform namespace but was classified as a customer workload", ns)
		}
	}
	for _, ns := range []string{"app-a", "pacman", "my-app", "edb", "nextcloud"} {
		if isSystemNamespace(ns) {
			t.Errorf("%q is a customer workload but was classified as system", ns)
		}
	}
}

// TestCustomerPolicyIsNotMistakenForASystemOne: KDL.sh anchors these names and
// says why. A prefix match silently drops a customer policy from coverage.
func TestCustomerPolicyIsNotMistakenForASystemOne(t *testing.T) {
	if !isSystemPolicy("k10-disaster-recovery-policy") {
		t.Error("the real K10 DR policy is no longer excluded")
	}
	for _, n := range []string{"k10-disaster-recovery-test", "k10-system-reports-mine", "my-report-policy"} {
		if isSystemPolicy(n) {
			t.Errorf("%q is a customer policy but was excluded as a system one", n)
		}
	}
}

// TestProtectionPeriodCountsWhateverItsType: Kasten emits protectionPeriod as
// seconds on some backends and as a duration string on others -- KDL.sh parses
// the "h" suffix, which is direct evidence live clusters return strings.
// Requiring a number scored those profiles as mutable, understating the single
// most important signal in the ransomware section.
func TestProtectionPeriodCountsWhateverItsType(t *testing.T) {
	for _, value := range []any{int64(2592000), float64(2592000), "2592000", "720h", "30d", "P30D"} {
		prof := unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "p"},
			"spec": map[string]any{"locationSpec": map[string]any{
				"objectStore": map[string]any{"objectStoreType": "S3", "protectionPeriod": value}}},
		}}
		r := buildFrom(t, map[string][]unstructured.Unstructured{"profiles": {prof}})
		if r.Profiles.ImmutableCount != 1 {
			t.Errorf("protectionPeriod=%v (%T): immutableCount = %d, want 1",
				value, value, r.Profiles.ImmutableCount)
		}
		if !r.ImmutabilitySignal {
			t.Errorf("protectionPeriod=%v (%T): immutabilitySignal is false", value, value)
		}
	}
	// An absent or empty value must still count as no immutability.
	for _, value := range []any{nil, ""} {
		prof := unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "p"},
			"spec":     map[string]any{"locationSpec": map[string]any{"objectStore": map[string]any{"protectionPeriod": value}}},
		}}
		if r := buildFrom(t, map[string][]unstructured.Unstructured{"profiles": {prof}}); r.Profiles.ImmutableCount != 0 {
			t.Errorf("protectionPeriod=%v: immutableCount = %d, want 0", value, r.Profiles.ImmutableCount)
		}
	}
}

// TestSelectorKindUsesKastenVocabulary: "all" was invented here; the emitter
// writes "catchall". An invented word is how a real value ends up misclassified.
func TestSelectorKindUsesKastenVocabulary(t *testing.T) {
	if got := selectorKind(kdl.PolicySelector{All: true}); got != "catchall" {
		t.Errorf("selectorKind(catch-all) = %q, want %q -- the word KDL emits", got, "catchall")
	}
}

// TestEveryCollectedTargetFeedsTheReport: an unused read costs API load and
// RBAC surface, and a denial on one of them flags the whole report as
// RBAC-degraded over data no section consumes.
func TestEveryCollectedTargetFeedsTheReport(t *testing.T) {
	consumed := map[string]bool{
		"namespaces": true, "storageClasses": true, "volumeSnapshotClasses": true,
		"k10Pods": true, "k10Deployments": true, "policies": true, "profiles": true,
		"policyPresets": true, "transformSets": true, "blueprintBindings": true,
		"blueprints": true, "backupActions": true, "exportActions": true,
		"restoreActions": true, "restorePoints": true, "clusterRoles": true,
		"clusterRoleBindings": true, "roles": true, "roleBindings": true,
		"routes": true, "scc": true, "virtualMachines": true,
	}
	for _, tg := range targets("kasten-io") {
		if !consumed[tg.key] {
			t.Errorf("target %q is collected but no section reads it; drop it or wire it up", tg.key)
		}
	}
}

// TestImmutabilityDaysSurvivesDurationShapes: the fix that made duration
// strings count as immutable left the magnitude at zero, so the report read
// "immutability enabled, 0 days" on exactly the shapes just repaired.
func TestImmutabilityDaysSurvivesDurationShapes(t *testing.T) {
	for _, tc := range []struct {
		value any
		days  int
	}{
		{int64(2592000), 30}, {"2592000", 30}, {"720h", 30}, {"30d", 30}, {"P30D", 30},
	} {
		prof := unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "p"},
			"spec": map[string]any{"locationSpec": map[string]any{
				"objectStore": map[string]any{"protectionPeriod": tc.value}}},
		}}
		r := buildFrom(t, map[string][]unstructured.Unstructured{"profiles": {prof}})
		if !r.ImmutabilitySignal {
			t.Errorf("protectionPeriod=%v: signal is false", tc.value)
		}
		if r.ImmutabilityDays != tc.days {
			t.Errorf("protectionPeriod=%v: immutabilityDays = %d, want %d",
				tc.value, r.ImmutabilityDays, tc.days)
		}
	}
}

// TestNoFalseRBACClaimOnTheLicenceSection: the licence section is not collected
// at all, which unpopulatedSections declares. Marking node consumption "not
// assessed" as well made the report say the node listing was denied by RBAC --
// and nothing was denied, because the node read is not attempted.
func TestNoFalseRBACClaimOnTheLicenceSection(t *testing.T) {
	r := buildFrom(t, map[string][]unstructured.Unstructured{})

	if r.License.NodeConsumption.Assessed != nil {
		t.Error("node consumption is annotated as unassessed, which the renderer reports as an RBAC denial")
	}
	if !contains(UnpopulatedSections(), "license") {
		t.Error("the licence section must still be declared uncollected")
	}
}
