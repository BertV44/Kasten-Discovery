package scan

import k8sschema "k8s.io/apimachinery/pkg/runtime/schema"

// The resources KDL reads, taken from the `kubectl get` calls of KDL.sh
// (branch dev-2.2.0-kasten-v9) rather than from the Kasten documentation: the
// shell tool is what runs against real customer clusters, so its resource list
// is the validated one.
//
// Everything here is read with the dynamic client into unstructured objects on
// purpose. Typed CRD structs would have to be transcribed from a schema no
// sample in this repository exercises, and a field that moved one level deep
// would then decode as a zero value -- which is exactly how comparing a profile
// state against an invented word once painted seven healthy profiles red.
// Unstructured plus a bounded deep scan (see unstruct.go) degrades to "not
// found" instead of to a confident wrong answer.
var (
	// Core Kubernetes.
	gvrNamespaces = k8sschema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	gvrPods       = k8sschema.GroupVersionResource{Version: "v1", Resource: "pods"}

	gvrDeployments = k8sschema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	gvrStorageClasses = k8sschema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "storageclasses"}
	gvrVolumeSnapClas = k8sschema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}

	gvrClusterRoles        = k8sschema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}
	gvrClusterRoleBindings = k8sschema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}
	gvrRoles               = k8sschema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
	gvrRoleBindings        = k8sschema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}

	// Kasten K10.
	gvrPolicies       = k8sschema.GroupVersionResource{Group: "config.kio.kasten.io", Version: "v1alpha1", Resource: "policies"}
	gvrProfiles       = k8sschema.GroupVersionResource{Group: "config.kio.kasten.io", Version: "v1alpha1", Resource: "profiles"}
	gvrPolicyPresets  = k8sschema.GroupVersionResource{Group: "config.kio.kasten.io", Version: "v1alpha1", Resource: "policypresets"}
	gvrTransformSets  = k8sschema.GroupVersionResource{Group: "config.kio.kasten.io", Version: "v1alpha1", Resource: "transformsets"}
	gvrBlueprintBinds = k8sschema.GroupVersionResource{Group: "config.kio.kasten.io", Version: "v1alpha1", Resource: "blueprintbindings"}

	gvrRunActions     = k8sschema.GroupVersionResource{Group: "actions.kio.kasten.io", Version: "v1alpha1", Resource: "runactions"}
	gvrBackupActions  = k8sschema.GroupVersionResource{Group: "actions.kio.kasten.io", Version: "v1alpha1", Resource: "backupactions"}
	gvrExportActions  = k8sschema.GroupVersionResource{Group: "actions.kio.kasten.io", Version: "v1alpha1", Resource: "exportactions"}
	gvrRestoreActions = k8sschema.GroupVersionResource{Group: "actions.kio.kasten.io", Version: "v1alpha1", Resource: "restoreactions"}

	gvrRestorePoints = k8sschema.GroupVersionResource{Group: "apps.kio.kasten.io", Version: "v1alpha1", Resource: "restorepoints"}

	gvrBlueprints = k8sschema.GroupVersionResource{Group: "cr.kanister.io", Version: "v1alpha1", Resource: "blueprints"}

	// Platform detection and virtualization.
	gvrRoutes          = k8sschema.GroupVersionResource{Group: "route.openshift.io", Version: "v1", Resource: "routes"}
	gvrVirtualMachines = k8sschema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
	gvrSCC             = k8sschema.GroupVersionResource{Group: "security.openshift.io", Version: "v1", Resource: "securitycontextconstraints"}
)

// target names one collection job. Namespaced targets are read from the Kasten
// namespace only; the rest are cluster-wide.
type target struct {
	// key names the collection in the result map and in any RBAC denial message,
	// so it must read well in "denied: <key>".
	key string
	gvr k8sschema.GroupVersionResource
	// namespaced reads from the Kasten install namespace rather than cluster-wide.
	namespaced bool
	// optional marks a resource whose absence is normal: no KubeVirt on a cluster
	// without virtualization, no routes off OpenShift. Absence of an optional
	// resource is not a gap in the report.
	optional bool
}

// targets is the full collection plan. Order is irrelevant -- they are fetched
// concurrently -- but keeping it grouped keeps the diff readable when a
// resource is added for a new Kasten release.
//
// Every entry must feed a section of the report. Six did not (nodes, secrets,
// PVCs, runActions, reportActions, kubeVirts) and were removed: an unused read
// costs API load, costs RBAC surface -- reading Secrets in the Kasten namespace
// is a sensitive ask, and it was being made for nothing -- and, worst, a denial
// on one of them set rbacLimited on the whole report, flagging it as
// RBAC-degraded because a read that feeds no section was refused. Add them back
// together with the code that consumes them, not before.
//
// runActions came back on those terms: policyRunStats (runstats.go) is the code
// that consumes it, and nothing else in the report needs it.
func targets(kastenNS string) []target {
	_ = kastenNS // namespace is applied by the collector, listed here for clarity
	return []target{
		{key: "namespaces", gvr: gvrNamespaces},
		{key: "storageClasses", gvr: gvrStorageClasses},
		{key: "volumeSnapshotClasses", gvr: gvrVolumeSnapClas, optional: true},

		{key: "k10Pods", gvr: gvrPods, namespaced: true},
		{key: "k10Deployments", gvr: gvrDeployments, namespaced: true},

		{key: "policies", gvr: gvrPolicies},
		{key: "profiles", gvr: gvrProfiles},
		{key: "policyPresets", gvr: gvrPolicyPresets, optional: true},
		{key: "transformSets", gvr: gvrTransformSets, optional: true},
		{key: "blueprintBindings", gvr: gvrBlueprintBinds, optional: true},
		{key: "blueprints", gvr: gvrBlueprints, optional: true},

		// RunActions are the per-policy run records. They are the only objects
		// carrying startTime and endTime, so every duration in the report comes
		// from here rather than from the per-object actions.
		{key: "runActions", gvr: gvrRunActions},
		{key: "backupActions", gvr: gvrBackupActions},
		{key: "exportActions", gvr: gvrExportActions},
		{key: "restoreActions", gvr: gvrRestoreActions},
		{key: "restorePoints", gvr: gvrRestorePoints, optional: true},

		{key: "clusterRoles", gvr: gvrClusterRoles},
		{key: "clusterRoleBindings", gvr: gvrClusterRoleBindings},
		{key: "roles", gvr: gvrRoles, namespaced: true},
		{key: "roleBindings", gvr: gvrRoleBindings, namespaced: true},

		{key: "routes", gvr: gvrRoutes, namespaced: true, optional: true},
		{key: "scc", gvr: gvrSCC, optional: true},
		{key: "virtualMachines", gvr: gvrVirtualMachines, optional: true},
	}
}
