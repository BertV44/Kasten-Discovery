package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// helmRelease builds a Helm release object the way Helm stores one: the release
// JSON gzipped, base64-encoded, and base64-encoded again by the API's own secret
// serialisation.
func helmRelease(revision string, values map[string]any) unstructured.Unstructured {
	payload, err := json.Marshal(map[string]any{
		"name":   "k10",
		"config": values,
		// A real release also carries the rendered manifests. They are included
		// here so the test proves the decoder reads only `config`.
		"manifest": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: not-read\n",
	})
	if err != nil {
		panic(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(payload); err != nil {
		panic(err)
	}
	zw.Close()

	inner := base64.StdEncoding.EncodeToString(gz.Bytes())
	outer := base64.StdEncoding.EncodeToString([]byte(inner))

	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      "sh.helm.release.v1.k10." + revision,
			"namespace": "kasten-io",
			"labels":    map[string]any{"name": "k10", "owner": "helm"},
		},
		"data": map[string]any{"release": outer},
	}}
}

func k10ConfigMap(data map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": k10ConfigMapName, "namespace": "kasten-io"},
		"data":       data,
	}}
}

// TestHelmValuesAreTheAuthoritativeSource: the release object holds what the
// operator actually supplied, and nothing else answers for settings K10 never
// writes elsewhere.
func TestHelmValuesAreTheAuthoritativeSource(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {helmRelease("v3", map[string]any{
			"auth": map[string]any{
				"oidcAuth": map[string]any{
					"enabled":     true,
					"providerURL": "https://sso.example.com",
				},
			},
			"limiter":  map[string]any{"csiSnapshotsPerCluster": float64(25)},
			"logLevel": "debug",
			"fips":     map[string]any{"enabled": true},
		})},
	})

	k := r.K10Configuration
	if k.Source != sourceHelmSecret {
		t.Fatalf("source = %q, want %q", k.Source, sourceHelmSecret)
	}
	if k.Security.Authentication.Method != "OIDC" {
		t.Errorf("auth method = %q, want OIDC", k.Security.Authentication.Method)
	}
	if k.Security.Authentication.Details != "https://sso.example.com" {
		t.Errorf("auth details = %q, want the provider URL", k.Security.Authentication.Details)
	}
	if !k.Security.FIPSMode {
		t.Error("fipsMode = false, but the values enable it")
	}
	// A number from JSON arrives as a float64, and "25.000000" in a report is a
	// value nobody can compare against a default.
	if got := k.ConcurrencyLimiters.CSISnapshotsPerCluster; got != "25" {
		t.Errorf("csiSnapshotsPerCluster = %q, want %q", got, "25")
	}
	if k.LogLevel != "debug" {
		t.Errorf("logLevel = %q, want debug", k.LogLevel)
	}
	if r.NotCollected("k10Configuration") {
		t.Error("k10Configuration is declared unpopulated even though the Helm values were read")
	}
}

// TestNewestHelmRevisionWins: Helm keeps one object per revision, and reading an
// older one reports settings that were replaced.
func TestNewestHelmRevisionWins(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {
			helmRelease("v1", map[string]any{"logLevel": "info"}),
			helmRelease("v9", map[string]any{"logLevel": "error"}),
			helmRelease("v2", map[string]any{"logLevel": "warn"}),
		},
	})
	if got := r.K10Configuration.LogLevel; got != "error" {
		t.Errorf("logLevel = %q, want error from revision 9", got)
	}
}

// TestConfigMapAnswersWhenHelmDoesNot: installs configured through ConfigMap
// overrides are the reason the fallback exists, and its keys are already the
// dotted paths.
func TestConfigMapAnswersWhenHelmDoesNot(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"configmaps": {k10ConfigMap(map[string]any{
			"limiter.snapshotExportsPerCluster": "40",
			"timeout.jobWait":                   "1200",
		})},
	})

	k := r.K10Configuration
	if k.Source != sourceConfigMap {
		t.Fatalf("source = %q, want %q", k.Source, sourceConfigMap)
	}
	if k.ConcurrencyLimiters.SnapshotExportsPerCluster != "40" {
		t.Errorf("exports limiter = %q, want 40 from the ConfigMap",
			k.ConcurrencyLimiters.SnapshotExportsPerCluster)
	}
	if k.Timeouts.JobWait != "1200" {
		t.Errorf("jobWait = %q, want 1200 from the ConfigMap", k.Timeouts.JobWait)
	}
	// The rest are K10's own defaults, which is a real answer, and the source
	// field is what tells the reader which is which.
	if k.Timeouts.BlueprintBackup != "45" {
		t.Errorf("blueprintBackup = %q, want the documented default 45", k.Timeouts.BlueprintBackup)
	}
}

// TestNoConfigSourceIsUnknownNotInsecure is the finding this section must never
// invent. A page of K10 defaults presented as this cluster's settings says
// nothing while looking complete, and "Authentication: none" is among the most
// alarming lines the report can carry.
func TestNoConfigSourceIsUnknownNotInsecure(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{})

	if got := r.K10Configuration.Source; got != sourceNone {
		t.Fatalf("source = %q, want %q", got, sourceNone)
	}
	if got := r.K10Configuration.Security.Authentication.Method; got != "unknown" {
		t.Errorf("auth method = %q, want unknown: nothing was read, so 'none' would be a claim nobody checked", got)
	}
	if !r.NotCollected("k10Configuration") {
		t.Error("k10Configuration is not declared unpopulated, but neither source answered")
	}
}

// TestSkipHelmIsRecordedAndNotAttempted: -no-helm is an operator's decision, and
// the report has to say so -- a configuration section built without the Helm
// values looks nothing like one where the read failed.
func TestSkipHelmIsRecordedAndNotAttempted(t *testing.T) {
	f := &fakeReader{lists: map[string][]unstructured.Unstructured{
		"secrets": {helmRelease("v1", map[string]any{"logLevel": "debug"})},
	}}
	served := map[string]bool{}
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		served[tg.gvr.Resource] = true
	}
	f.served = served

	res := Collect(context.Background(), f,
		Options{KastenNamespace: "kasten-io", Parallelism: 4, SkipHelm: true})
	res.CollectedAt = testNow
	r := Build(res)

	if _, attempted := res.Collections["helmRelease"]; attempted {
		t.Error("the Helm release was still read with -no-helm; skipping means not issuing the request")
	}
	if !r.CollectionFlags.SkipHelm {
		t.Error("collectionFlags.skipHelm is false, so the report does not record the operator's choice")
	}
	if got := r.K10Configuration.Source; got != sourceSkipped {
		t.Errorf("source = %q, want %q", got, sourceSkipped)
	}
	if r.K10Configuration.LogLevel != "info" {
		t.Errorf("logLevel = %q, want the default: the values must not have been read",
			r.K10Configuration.LogLevel)
	}
}

// TestExplicitFalseIsNotOverriddenByDetection: networkPolicy.create=false is a
// decision. A NetworkPolicy left behind by something else must not flip it.
func TestExplicitFalseIsNotOverriddenByDetection(t *testing.T) {
	netpol := obj("NetworkPolicy", "k10-allow", nil)

	withValue := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {helmRelease("v1", map[string]any{
			"networkPolicy": map[string]any{"create": false},
		})},
		"networkpolicies": {netpol},
	})
	if withValue.K10Configuration.Security.NetworkPolicies {
		t.Error("networkPolicies = true, but the values explicitly say create=false")
	}

	// With no value either way, the object's presence is the only evidence there
	// is, and it is good evidence.
	withoutValue := buildAt(t, map[string][]unstructured.Unstructured{
		"configmaps":      {k10ConfigMap(map[string]any{"logLevel": "info"})},
		"networkpolicies": {netpol},
	})
	if !withoutValue.K10Configuration.Security.NetworkPolicies {
		t.Error("networkPolicies = false, but a K10 NetworkPolicy exists and nothing said otherwise")
	}
}

// TestExcludedAppsAcceptsBothSpellings: Helm values carry a list, the ConfigMap
// carries one comma-separated string, and reading only one of them reports a
// cluster with deliberate opt-outs as having none.
func TestExcludedAppsAcceptsBothSpellings(t *testing.T) {
	fromHelm := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {helmRelease("v1", map[string]any{
			"excludedApps": []any{"team-scratch", "ci-sandbox"},
		})},
	})
	if got := fromHelm.K10Configuration.ExcludedApps; got.Count != 2 {
		t.Errorf("excludedApps from Helm = %+v, want 2 items", got)
	}

	fromCM := buildAt(t, map[string][]unstructured.Unstructured{
		"configmaps": {k10ConfigMap(map[string]any{"excludedApps": "team-scratch, ci-sandbox"})},
	})
	if got := fromCM.K10Configuration.ExcludedApps; got.Count != 2 {
		t.Errorf("excludedApps from ConfigMap = %+v, want 2 items", got)
	}
}

// TestUnprotectedBreakdownSubtractsOnlyRealDecisions: the split exists so the
// headline count is actionable, and it must fail toward "actionable" -- hiding a
// real gap behind an exclusion nobody configured costs the data.
func TestUnprotectedBreakdownSubtractsOnlyRealDecisions(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {
			obj("Namespace", "unprotected-real", nil),
			obj("Namespace", "excluded-globally", nil),
			obj("Namespace", "excluded-by-policy", nil),
		},
		"policies": {policy("selective", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchExpressions": []any{
				map[string]any{
					"key":      "k10.kasten.io/appNamespace",
					"operator": "NotIn",
					"values":   []any{"excluded-by-policy"},
				},
			}},
		})},
		"secrets": {helmRelease("v1", map[string]any{
			"excludedApps": []any{"excluded-globally"},
		})},
	})

	bd := r.Coverage.UnprotectedBreakdown
	if bd == nil {
		t.Fatal("unprotectedBreakdown is absent")
	}
	if bd.Total != 3 {
		t.Fatalf("total = %d, want 3: %+v", bd.Total, r.Coverage.UnprotectedNamespaces.Items)
	}
	if bd.ExcludedByHelm != 1 || bd.ExcludedByPolicy != 1 || bd.DeliberatelyExcluded != 2 {
		t.Errorf("breakdown = %+v, want 1 by Helm, 1 by policy, 2 deliberate", *bd)
	}
	if bd.Actionable != 1 || len(bd.ActionableNamespaces) != 1 ||
		bd.ActionableNamespaces[0] != "unprotected-real" {
		t.Errorf("actionable = %+v, want just unprotected-real", bd.ActionableNamespaces)
	}
	if bd.DeliberatelyExcluded+bd.Actionable != bd.Total {
		t.Errorf("breakdown = %+v: the two halves must add up to the total", *bd)
	}
}

// TestPolicyExclusionsResolveTheirPatterns: a pattern alone does not say whether
// anything is excluded -- "kube-*" excludes nothing on a cluster with no kube-
// namespace -- and a reader shown only the pattern cannot tell those apart.
func TestPolicyExclusionsResolveTheirPatterns(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "team-a", nil), obj("Namespace", "team-b", nil)},
		"policies": {policy("wildcards", map[string]any{
			"actions": []any{map[string]any{"action": "backup"}},
			"selector": map[string]any{"matchExpressions": []any{
				map[string]any{
					"key":      "k10.kasten.io/appNamespace",
					"operator": "NotIn",
					"values":   []any{"team-b", "nothing-matches-*"},
				},
			}},
		})},
	})

	pe := r.K10Configuration.PolicyExclusions
	if pe == nil || pe.Count != 1 {
		t.Fatalf("policyExclusions = %+v, want one policy", pe)
	}
	ex := pe.ByPolicy[0]
	if len(ex.Patterns) != 2 {
		t.Errorf("patterns = %v, want both values kept", ex.Patterns)
	}
	if len(ex.MatchedNamespaces) != 1 || ex.MatchedNamespaces[0] != "team-b" {
		t.Errorf("matchedNamespaces = %v, want just team-b: the second pattern matches nothing live",
			ex.MatchedNamespaces)
	}
}

// TestMultiClusterRoleDecidesWhichFieldsApply: on a secondary the primary's name
// is the section's whole point, and both spellings of the join keys are in the
// field.
func TestMultiClusterRoleDecidesWhichFieldsApply(t *testing.T) {
	primary := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", mcNamespace, nil)},
		"clusters":   {obj("Cluster", "edge-1", nil), obj("Cluster", "edge-2", nil)},
	})
	if primary.MultiCluster.Role != "primary" {
		t.Errorf("role = %q, want primary", primary.MultiCluster.Role)
	}
	if c := primary.MultiCluster.ClusterCount; c == nil || *c != 2 {
		t.Errorf("clusterCount = %v, want 2 joined clusters", c)
	}

	secondary := buildAt(t, map[string][]unstructured.Unstructured{
		"configmaps": {unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": mcJoinConfigMap, "namespace": "kasten-io"},
			"data":       map[string]any{"primary": "hq-cluster", "clusterID": "abc-123"},
		}}},
	})
	mc := secondary.MultiCluster
	if mc.Role != "secondary" {
		t.Fatalf("role = %q, want secondary", mc.Role)
	}
	if mc.PrimaryName == nil || *mc.PrimaryName != "hq-cluster" {
		t.Errorf("primaryName = %v, want hq-cluster from the alternate key spelling", mc.PrimaryName)
	}
	if mc.ClusterID == nil || *mc.ClusterID != "abc-123" {
		t.Errorf("clusterId = %v, want abc-123", mc.ClusterID)
	}

	standalone := buildAt(t, map[string][]unstructured.Unstructured{
		"namespaces": {obj("Namespace", "kasten-io", nil)},
	})
	if standalone.MultiCluster.Role != "none" {
		t.Errorf("role = %q, want none on a standalone cluster", standalone.MultiCluster.Role)
	}
	if standalone.MultiCluster.PrimaryName != nil {
		t.Errorf("primaryName = %v, want null off a secondary", *standalone.MultiCluster.PrimaryName)
	}
	// Only a primary manages clusters. Zero would read as a primary managing none.
	if c := standalone.MultiCluster.ClusterCount; c != nil {
		t.Errorf("clusterCount = %d on a standalone cluster, want null", *c)
	}
}

// TestTunedSettingsCountsWhatSomebodyChose: an operator reading four tables of
// numbers cannot tell which of them is a decision.
func TestTunedSettingsCountsWhatSomebodyChose(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {helmRelease("v1", map[string]any{
			"limiter":  map[string]any{"csiSnapshotsPerCluster": float64(25)},
			"logLevel": "debug",
		})},
	})
	nd := r.K10Configuration.NonDefaultSettings
	if nd.Count != 2 {
		t.Errorf("nonDefaultSettings = %+v, want 2 (csiSnapshots and logLevel)", nd)
	}
	if nd.Items == nil {
		t.Fatal("nonDefaultSettings.items is null with a non-zero count")
	}
}
