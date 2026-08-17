package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BertV44/Kasten-Discovery/internal/report"
	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A collection resembling a small but complete cluster, used to prove the
// collector's output is a report the rest of the toolchain accepts.
func sampleCluster() map[string][]unstructured.Unstructured {
	action := func(name, state string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": name},
			"status":   map[string]any{"state": state},
		}}
	}
	return map[string][]unstructured.Unstructured{
		"namespaces": {
			obj("Namespace", "app-a", nil),
			obj("Namespace", "app-b", nil),
			obj("Namespace", "kube-system", nil),
		},
		"policies": {
			policy("backup-a", map[string]any{
				"frequency": "@daily",
				"actions": []any{
					map[string]any{"action": "backup"},
					map[string]any{"action": "export", "exportParameters": map[string]any{
						"profile": map[string]any{"name": "s3"}}},
				},
				"retention": map[string]any{"daily": int64(7)},
				"selector": map[string]any{"matchExpressions": []any{
					map[string]any{"key": "k10.kasten.io/appNamespace", "operator": "In", "values": []any{"app-a"}},
				}},
			}),
		},
		"profiles": {
			unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{"name": "s3"},
				"spec": map[string]any{"locationSpec": map[string]any{
					"objectStore": map[string]any{"objectStoreType": "S3", "region": "eu-west-1"}}},
			}},
		},
		"backupactions": {action("b1", "Complete"), action("b2", "Failed")},
		"exportactions": {action("e1", "Complete")},
		"storageclasses": {
			obj("StorageClass", "fast", map[string]any{"provisioner": "csi.example.com", "reclaimPolicy": "Delete"}),
		},
	}
}

// TestScanOutputDecodesStrictly is the contract check between the collector and
// the schema: the report JSON `kdl scan` writes must survive the same strict
// decode `kdl validate` performs. A key the schema does not model, or a type it
// models differently, fails here rather than in front of a customer.
func TestScanOutputDecodesStrictly(t *testing.T) {
	built := Build(collect(t, &fakeReader{lists: sampleCluster()}))

	encoded, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("encoding the collected report: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	var decoded kdl.Report
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("the collector emitted a report the schema rejects: %v", err)
	}

	if decoded.Policies.Count != built.Policies.Count {
		t.Errorf("policy count did not survive the round trip: %d vs %d",
			decoded.Policies.Count, built.Policies.Count)
	}
}

// TestScanOutputRenders proves the collector and the renderer agree end to end:
// a report collected from a cluster must produce an HTML page, not a template
// error on a section the collector left at its zero value.
func TestScanOutputRenders(t *testing.T) {
	built := Build(collect(t, &fakeReader{lists: sampleCluster()}))

	var buf bytes.Buffer
	if err := report.Render(built, &buf, report.Options{}); err != nil {
		t.Fatalf("rendering a collected report: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "backup-a") {
		t.Error("the rendered page does not mention the collected policy")
	}
	if !strings.Contains(html, "app-b") {
		t.Error("the rendered page does not mention the unprotected namespace")
	}
}

// TestCountsMatchTheirLists: a count that disagrees with its list is the
// signature of a collector that silently dropped elements, and `kdl validate`
// rejects a report where the two disagree.
func TestCountsMatchTheirLists(t *testing.T) {
	r := Build(collect(t, &fakeReader{lists: sampleCluster()}))

	if got := len(r.Policies.Items); got != r.Policies.Count {
		t.Errorf("policies.count = %d but items holds %d", r.Policies.Count, got)
	}
	if got := len(r.Profiles.Items); got != r.Profiles.Count {
		t.Errorf("profiles.count = %d but items holds %d", r.Profiles.Count, got)
	}
	if got := len(r.StorageClasses.Items); got != r.StorageClasses.Count {
		t.Errorf("storageClasses.count = %d but items holds %d", r.StorageClasses.Count, got)
	}
	if got := len(r.Coverage.UnprotectedNamespaces.Items); got != r.Coverage.UnprotectedNamespaces.Count {
		t.Errorf("unprotectedNamespaces.count = %d but items holds %d",
			r.Coverage.UnprotectedNamespaces.Count, got)
	}
}

// TestSystemNamespacesAreNotReportedUnprotected: kube-system is not a workload
// a customer forgot to back up.
func TestSystemNamespacesAreNotReportedUnprotected(t *testing.T) {
	r := Build(collect(t, &fakeReader{lists: sampleCluster()}))

	if contains(r.Coverage.UnprotectedNamespaces.Items, "kube-system") {
		t.Errorf("unprotected = %v, want system namespaces excluded",
			r.Coverage.UnprotectedNamespaces.Items)
	}
	if !contains(r.Coverage.UnprotectedNamespaces.Items, "app-b") {
		t.Errorf("unprotected = %v, want app-b: no policy selects it",
			r.Coverage.UnprotectedNamespaces.Items)
	}
}
