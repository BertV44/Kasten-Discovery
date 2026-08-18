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

	gvrConfigMaps = k8sschema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	gvrServices   = k8sschema.GroupVersionResource{Version: "v1", Resource: "services"}
	// Secrets are read once, by label, for the Helm release object only -- see
	// the helmRelease target below.
	gvrSecrets = k8sschema.GroupVersionResource{Version: "v1", Resource: "secrets"}

	gvrIngresses       = k8sschema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}
	gvrNetworkPolicies = k8sschema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	gvrMutatingWebhook = k8sschema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}

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

	// Multi-cluster: the joined-cluster records a primary holds.
	gvrMCClusters = k8sschema.GroupVersionResource{Group: "dist.kio.kasten.io", Version: "v1alpha1", Resource: "clusters"}

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
	// labelSelector narrows the read server-side. Only the Helm release read
	// uses it, and it is not a convenience there: without it the collector would
	// have to list every Secret in the Kasten namespace to find one object.
	labelSelector string
}

// Options are the collection knobs a caller sets. They are a struct rather than
// a parameter list because SkipHelm has to reach the plan itself: skipping the
// Helm read means not issuing it, not discarding its result afterwards.
type Options struct {
	// KastenNamespace is where K10 is installed.
	KastenNamespace string
	// Parallelism bounds concurrent fetches.
	Parallelism int
	// SkipHelm drops the Helm release read, for environments where reading the
	// release object is not acceptable. The report records the choice in
	// collectionFlags.skipHelm and in k10Configuration.source, because a
	// configuration section built without it is full of defaults and looks
	// nothing like an unreadable one.
	SkipHelm bool
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
func targets(opts Options) []target {
	plan := []target{
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

		// K10's own configuration. The ConfigMap is the fallback source for every
		// setting the Helm values would otherwise answer, and also carries the
		// multi-cluster join record.
		{key: "k10ConfigMaps", gvr: gvrConfigMaps, namespaced: true},
		{key: "k10Services", gvr: gvrServices, namespaced: true},
		{key: "k10Ingresses", gvr: gvrIngresses, namespaced: true, optional: true},
		{key: "k10NetworkPolicies", gvr: gvrNetworkPolicies, namespaced: true, optional: true},
		{key: "mutatingWebhooks", gvr: gvrMutatingWebhook, optional: true},
		{key: "mcClusters", gvr: gvrMCClusters, optional: true},
	}

	// The Helm release object holds the values the operator supplied at install
	// time, and nothing else answers for settings K10 never writes elsewhere.
	//
	// It is a Secret, which is the most sensitive read in the plan, so it is the
	// narrowest: one label-selected object, from which only the `config` member
	// is decoded. The rendered manifests in the rest of the payload are never
	// looked at, and no value from it is emitted verbatim except the specific
	// settings the section reports. -no-helm drops the read entirely.
	if !opts.SkipHelm {
		plan = append(plan, target{
			key: "helmRelease", gvr: gvrSecrets, namespaced: true, optional: true,
			labelSelector: "name=k10,owner=helm",
		})
	}
	return plan
}
