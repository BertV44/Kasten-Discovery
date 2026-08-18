package scan

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeReader serves canned objects and canned failures per resource, so the
// collector's handling of a denied read can be exercised without a cluster.
//
// It is a fake of the API surface only. It deliberately cannot validate CRD
// field shapes -- that is the assumption this repository has already paid for
// once, and no amount of fake-client testing substitutes for one real cluster.
type fakeReader struct {
	lists    map[string][]unstructured.Unstructured
	errs     map[string]error
	served   map[string]bool
	version  string
	discoErr error
	// volumeStats is what the kubelet on any node reports; volumeStatsErr stands
	// in for the RBAC denial that is the expected outcome on most clusters, since
	// get on nodes/proxy is not a permission K10 itself needs.
	volumeStats    []VolumeStat
	volumeStatsErr error
}

func (f *fakeReader) key(gvr k8sschema.GroupVersionResource) string { return gvr.Resource }

func (f *fakeReader) List(_ context.Context, gvr k8sschema.GroupVersionResource, _, _ string) (*unstructured.UnstructuredList, error) {
	k := f.key(gvr)
	if err, ok := f.errs[k]; ok {
		return nil, err
	}
	return &unstructured.UnstructuredList{Items: f.lists[k]}, nil
}

func (f *fakeReader) Get(_ context.Context, gvr k8sschema.GroupVersionResource, _, _ string) (*unstructured.Unstructured, error) {
	if err, ok := f.errs[f.key(gvr)]; ok {
		return nil, err
	}
	return &unstructured.Unstructured{}, nil
}

func (f *fakeReader) NodeVolumeStats(_ context.Context, _ string) ([]VolumeStat, error) {
	return f.volumeStats, f.volumeStatsErr
}

func (f *fakeReader) ServerVersion() (string, error) { return f.version, nil }

func (f *fakeReader) HasResource(gvr k8sschema.GroupVersionResource) (bool, error) {
	if f.discoErr != nil {
		return false, f.discoErr
	}
	if f.served == nil {
		return true, nil
	}
	return f.served[f.key(gvr)], nil
}

func forbidden(resource string) error {
	return apierrors.NewForbidden(
		k8sschema.GroupResource{Resource: resource}, "", errors.New("denied by RBAC"))
}

func obj(kind, name string, fields map[string]any) unstructured.Unstructured {
	o := map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
	}
	for k, v := range fields {
		o[k] = v
	}
	return unstructured.Unstructured{Object: o}
}

func collect(t *testing.T, f *fakeReader) Result {
	t.Helper()
	if f.served == nil {
		f.served = map[string]bool{}
		for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
			f.served[tg.gvr.Resource] = true
		}
	}
	return Collect(context.Background(), f, Options{KastenNamespace: "kasten-io", Parallelism: 4})
}

// TestDeniedReadIsNotAnEmptyRead is the whole point of the accessibility
// machinery: a section fed by a denied read is EMPTY, not zero. Collapsing the
// two turns a permissions problem into a clean bill of health.
func TestDeniedReadIsNotAnEmptyRead(t *testing.T) {
	res := collect(t, &fakeReader{
		errs: map[string]error{"policies": forbidden("policies")},
	})

	c := res.Get("policies")
	if !c.Denied {
		t.Error("a forbidden policy listing was not recorded as denied")
	}
	if c.OK() {
		t.Error("a denied collection must not report OK()")
	}
	if got := res.Denials(); len(got) != 1 || got[0] != "policies" {
		t.Errorf("Denials() = %v, want [policies]", got)
	}
}

// TestDenialsSurfaceInTheReport: a report collected by a restricted service
// account must say so, or it is indistinguishable from a report of an empty
// cluster.
func TestDenialsSurfaceInTheReport(t *testing.T) {
	r := Build(collect(t, &fakeReader{
		errs: map[string]error{
			"policies":   forbidden("policies"),
			"namespaces": forbidden("namespaces"),
		},
	}))

	if r.RBACLimited == nil || !r.RBACLimited.Any {
		t.Fatal("denied reads did not set rbacLimited")
	}
	if len(r.RBACLimited.Denied) != 2 {
		t.Errorf("denied = %v, want both resources named", r.RBACLimited.Denied)
	}
}

// TestDeniedPolicyReadDoesNotDeclareEveryNamespaceUnprotected: computing
// coverage from a denied policy listing would report every namespace in the
// cluster as unprotected -- the most alarming possible way to render a
// permissions problem.
func TestDeniedPolicyReadDoesNotDeclareEveryNamespaceUnprotected(t *testing.T) {
	r := Build(collect(t, &fakeReader{
		errs: map[string]error{"policies": forbidden("policies")},
		lists: map[string][]unstructured.Unstructured{
			"namespaces": {obj("Namespace", "app-a", nil), obj("Namespace", "app-b", nil)},
		},
	}))

	if got := r.Coverage.UnprotectedNamespaces.Count; got != 0 {
		t.Errorf("unprotected namespaces = %d, want 0: the policy listing was denied, so coverage is unknown, not total", got)
	}
	if r.Coverage.Note == "" {
		t.Error("coverage must say why it was not computed rather than silently reporting nothing")
	}
}

// TestAbsentResourceIsNotADenial: a cluster without KubeVirt has no VMs to
// report, and nothing is wrong. Conflating that with a denial would put a
// permissions warning on every non-virtualized cluster.
func TestAbsentResourceIsNotADenial(t *testing.T) {
	f := &fakeReader{served: map[string]bool{}}
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		f.served[tg.gvr.Resource] = true
	}
	f.served["virtualmachines"] = false

	res := collect(t, f)
	c := res.Get("virtualMachines")
	if !c.Absent {
		t.Error("a resource the cluster does not serve was not recorded as absent")
	}
	if c.Denied {
		t.Error("an absent resource must not be reported as an RBAC denial")
	}
	if len(res.Denials()) != 0 {
		t.Errorf("Denials() = %v, want empty", res.Denials())
	}
}

// TestPartialRBACReadIsNotFullyAccessible: an inventory assembled from three of
// four listings is incomplete, not complete-and-small.
func TestPartialRBACReadIsNotFullyAccessible(t *testing.T) {
	r := Build(collect(t, &fakeReader{
		errs: map[string]error{"rolebindings": forbidden("rolebindings")},
	}))

	if r.K10RBAC.Accessibility.FullyAccessible {
		t.Error("fullyAccessible is true while a RoleBinding listing was denied")
	}
	if r.K10RBAC.Accessibility.Note == "" {
		t.Error("an incomplete RBAC inventory must carry a note saying so")
	}
}

// TestEveryTargetIsCollected guards the collection plan against a target that
// is declared but never fetched, which would leave a section permanently empty
// with nothing saying why.
func TestEveryTargetIsCollected(t *testing.T) {
	res := collect(t, &fakeReader{})
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		if _, ok := res.Collections[tg.key]; !ok {
			t.Errorf("target %q was declared but never collected", tg.key)
		}
	}
}

// TestCollectSurvivesOneFailure: one broken read must cost one section, not the
// whole scan.
func TestCollectSurvivesOneFailure(t *testing.T) {
	res := collect(t, &fakeReader{
		errs:  map[string]error{"policies": errors.New("connection reset")},
		lists: map[string][]unstructured.Unstructured{"namespaces": {obj("Namespace", "a", nil)}},
	})

	if res.Get("policies").Err == nil {
		t.Error("the failing read did not record its error")
	}
	if !res.Get("namespaces").OK() {
		t.Error("a failure in one resource broke an unrelated one")
	}
}

// TestDiscoveryFailureIsNotAbsence: on an unreachable cluster, discovery
// answers "no" for every optional resource. Falling through to Absent then
// reports a total outage as "not served by this cluster (normal)" -- dressing
// up a failure as a normal configuration, which is the misleading zero applied
// to a whole scan.
func TestDiscoveryFailureIsNotAbsence(t *testing.T) {
	res := collect(t, &fakeReader{discoErr: errors.New("dial tcp: no route to host")})

	c := res.Get("virtualMachines")
	if c.Absent {
		t.Error("an unreachable cluster was reported as not serving the resource")
	}
	if c.Err == nil {
		t.Error("a discovery failure must be recorded as an error")
	}
}

// TestTotalFailureIsDetected: a report whose every section is zero because the
// cluster was never reached looks exactly like a cluster with nothing in it.
// kdl scan refuses to write one.
func TestTotalFailureIsDetected(t *testing.T) {
	all := map[string]error{}
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		all[tg.gvr.Resource] = errors.New("connection refused")
	}
	res := collect(t, &fakeReader{errs: all, discoErr: errors.New("connection refused")})

	if !res.TotalFailure() {
		t.Errorf("TotalFailure() = false with %d successful reads, want true", res.Succeeded())
	}
}

// TestPartialSuccessIsNotTotalFailure is the positive control: one working read
// means the cluster was reached, and the report is worth writing.
func TestPartialSuccessIsNotTotalFailure(t *testing.T) {
	all := map[string]error{}
	for _, tg := range targets(Options{KastenNamespace: "kasten-io"}) {
		all[tg.gvr.Resource] = errors.New("connection refused")
	}
	delete(all, "namespaces")

	res := collect(t, &fakeReader{
		errs:  all,
		lists: map[string][]unstructured.Unstructured{"namespaces": {obj("Namespace", "a", nil)}},
	})
	if res.TotalFailure() {
		t.Error("TotalFailure() = true while the namespace listing succeeded")
	}
}
