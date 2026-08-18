package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ScanVersion marks reports produced by this collector. It is deliberately not
// a KDL.sh version number: a consumer must be able to tell a Go-collected
// report from a shell-collected one, because the two do not yet populate the
// same set of sections.
const ScanVersion = "2.2.0-go"

// Build turns a collection into a report.
//
// Only sections this collector genuinely populates are filled. The rest are
// left at their zero value and listed by UnpopulatedSections, because a
// half-computed analysis section is worse than an absent one: it renders as a
// confident verdict over data that was never gathered.
func Build(res Result) *kdl.Report {
	r := &kdl.Report{
		KDLVersion:    ScanVersion,
		KastenVersion: kastenVersion(res),
		Platform:      platform(res),
	}

	buildRBACLimited(res, r)
	buildCompatibility(r)
	buildCluster(res, r)
	buildPolicies(res, r)
	buildProfiles(res, r)
	buildNamespaces(res, r)
	buildVirtualization(res, r)
	buildStorage(res, r)
	buildK10Resources(res, r)
	buildRBACInventory(res, r)
	buildHealth(res, r)
	buildMisc(res, r)
	buildCoverage(res, r)
	buildPolicyAnalysis(res, r)
	buildProfileValidation(res, r)
	buildFailedActions(res, r)
	// One instant for every age in the report: two calls to Now() would let a
	// stuck action and a stale namespace be measured against different clocks.
	now := res.Now()
	buildStuckActions(res, r, now)
	buildNamespaceProtection(res, r, now)
	buildPolicyRunStats(res, r, now)
	buildRetentionAnalysis(r)
	buildDisasterRecovery(res, r, now)
	buildMonitoring(res, r)
	buildRestorePointsByNamespace(res, r)
	buildOrphanedRestorePoints(res, r)
	markUnassessedChecks(r)

	// Declared in the report itself, not only on stderr. A consumer that cannot
	// tell "not computed" from "computed and empty" reads every uncollected
	// section as a cluster with nothing in it.
	r.UnpopulatedSections = unpopulatedFor(res)

	return r
}

// markUnassessedChecks writes NOT_ASSESSED into every best-practice check this
// collector does not compute.
//
// Leaving them empty is not neutral: the renderer reads an empty value as a
// status it does not recognise, which fails the check, which paints the two
// critical checks "✗ CRITICAL" and the report's verdict banner "2 Critical" --
// on a cluster where nobody looked at either. Emitting the word KDL itself uses
// for an unread value makes the renderer show them as not assessed instead.
//
// This is lesson four in both directions at once: an unassessed check must not
// be reported as failing, and must not be reported as passing either.
func markUnassessedChecks(r *kdl.Report) {
	bp := &r.BestPractices
	for _, field := range []*string{
		&bp.DisasterRecovery, &bp.Immutability, &bp.PolicyPresets, &bp.Monitoring,
		&bp.ResourceLimits, &bp.NamespaceProtection, &bp.VMProtection,
		&bp.Authentication, &bp.Encryption, &bp.AuditLogging,
		&bp.SnapshotRetentionHigh, &bp.SnapshotRetentionZero,
		&bp.ExportRetentionExplicit, &bp.ClusterScopedResources,
		&bp.PoliciesWithoutExport,
	} {
		if *field == "" {
			*field = kdl.StatusNotAssessed
		}
	}
	// The licence section is not collected at all, which unpopulatedSections
	// already declares. Marking node consumption "not assessed" here as well
	// made the report say "node listing denied by RBAC" -- and nothing was
	// denied: the node read is not attempted. Telling a customer RBAC blocked
	// something the tool never asked for is its own false claim, so the licence
	// section is left to the declaration and not annotated here.
}

// UnpopulatedSections names the report sections this collector does not yet
// compute. It is emitted in the scan summary rather than kept as a comment,
// because a user comparing a Go report against a KDL.sh one needs to know which
// empty sections are "nothing found" and which are "not implemented".
func UnpopulatedSections() []string {
	return []string{
		"ransomwareReadiness", "bestPractices", "dataUsage",
		"k10Configuration", "catalog", "multiCluster", "license",
		// policyAnalysis IS computed, but only partly: redundancy is not. Naming
		// the sub-path keeps the rest of the section comparable while stopping a
		// structural zero from reading as "21 redundant pairs resolved".
		"policyAnalysis.summary.redundantPairsGenuine",
	}
}

// sectionInputs names the collections each computed section is derived from.
//
// "Not implemented" is not the only way a section ends up empty: a section whose
// input was refused by RBAC or failed to read is equally uncomputed, and its
// zero value is equally indistinguishable from a real empty. Declaring those per
// run is what stops a scan by a restricted service account from diffing as a
// cluster that lost every restore point it had.
//
// Absence does not disqualify a section. A cluster that does not serve
// RestorePoints genuinely holds none, so zero there is a fact rather than a gap
// -- which is the whole reason Collection keeps Absent apart from Denied.
//
// Every requirement here is one the section is *wrong* without, not merely
// thinner. failedActionsTop5 names all three action listings because "the five
// most recent failures" computed from two of them is a claim about all three.
var sectionInputs = map[string][]string{
	"profileValidation":         {"profiles"},
	"failedActionsTop5":         {"backupActions", "exportActions", "restoreActions"},
	"stuckActions":              {"backupActions", "exportActions", "restoreActions"},
	"namespaceProtectionStatus": {"namespaces", "backupActions", "exportActions", "restoreActions"},
	"restorePointsByNamespace":  {"restorePoints"},
	"orphanedRestorePoints":     {"restorePoints", "policies"},
	"retentionAnalysis":         {"policies"},
	// All three policyRunStats sub-sections are measured from RunActions and are
	// named separately, because the diff compares effectiveRpo on its own.
	"policyRunStats.lastRuns":        {"policies", "runActions"},
	"policyRunStats.averageDuration": {"runActions"},
	"policyRunStats.effectiveRpo":    {"policies", "runActions"},
	// The DR verdict is derived from the DR policy's run history, so a report
	// that could not read either would otherwise announce NOT_ENABLED or
	// CONFIGURED_NOT_HEALTHY on a healthy install.
	"disasterRecovery": {"policies", "runActions"},
	"monitoring":       {"k10Pods"},
}

// unpopulatedFor is the list declared in one report: the sections this build
// cannot compute at all, plus the ones it can but whose input this run did not
// return.
func unpopulatedFor(res Result) []string {
	out := UnpopulatedSections()

	var degraded []string
	for section, inputs := range sectionInputs {
		for _, key := range inputs {
			if c, present := res.Collections[key]; !present || (!c.OK() && !c.Absent) {
				degraded = append(degraded, section)
				break
			}
		}
	}
	sort.Strings(degraded)
	return append(out, degraded...)
}

// buildRBACLimited records denied reads as a first-class result. Without it a
// report collected by a restricted service account is indistinguishable from a
// report of an empty cluster.
func buildRBACLimited(res Result, r *kdl.Report) {
	denials := res.Denials()
	if len(denials) == 0 {
		return
	}
	r.RBACLimited = &kdl.RBACLimited{Any: true, Denied: denials}
}

// KastenValidatedUpTo is the highest Kasten release this build's field paths
// were reasoned about, mirroring KDL.sh's KDL_KASTEN_TESTED_MAX. Bump it only
// together with the paths themselves.
const KastenValidatedUpTo = "9.0"

// buildCompatibility warns when the cluster runs a Kasten newer than this build
// understands. It matters more here than in the shell tool: these field paths
// have never been exercised against a live cluster, so "newer than validated"
// is the reader's cue that a missing value may be a moved field rather than an
// absent one.
func buildCompatibility(r *kdl.Report) {
	c := &kdl.KastenCompatibility{ValidatedUpTo: KastenValidatedUpTo}
	if mm, ok := majorMinor(r.KastenVersion); ok {
		c.DetectedMajorMinor = &mm
		c.NewerThanValidated = newerThan(mm, KastenValidatedUpTo)
	}
	// DetectedMajorMinor stays nil when the version could not be parsed, which
	// is not the same as the cluster running an old release.
	r.KastenCompatibility = c
}

// majorMinor extracts "9.0" from "9.0.3" or "v9.0.3-rc1". It reports failure
// rather than guessing, because a wrong major.minor drives a wrong
// compatibility verdict.
func majorMinor(version string) (string, bool) {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if v == "" || v == "unknown" || v == "digest-based" {
		return "", false
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "", false
	}
	major, errA := strconv.Atoi(parts[0])
	minorField, _, _ := strings.Cut(parts[1], "-")
	minor, errB := strconv.Atoi(minorField)
	if errA != nil || errB != nil {
		return "", false
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor), true
}

// newerThan compares two "major.minor" strings numerically. String comparison
// would put "9.10" before "9.2".
func newerThan(got, reference string) bool {
	gMaj, gMin, okA := splitMajorMinor(got)
	rMaj, rMin, okB := splitMajorMinor(reference)
	if !okA || !okB {
		return false
	}
	if gMaj != rMaj {
		return gMaj > rMaj
	}
	return gMin > rMin
}

func splitMajorMinor(v string) (int, int, bool) {
	major, minor, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, false
	}
	a, errA := strconv.Atoi(major)
	b, errB := strconv.Atoi(minor)
	return a, b, errA == nil && errB == nil
}

func kastenVersion(res Result) string {
	// KDL.sh reads the version off the catalog deployment's
	// app.kubernetes.io/version label, falling back to the image tag.
	for _, d := range res.Items("k10Deployments") {
		labels := d.GetLabels()
		if labels["component"] != "catalog" {
			continue
		}
		if v := labels["app.kubernetes.io/version"]; v != "" {
			return v
		}
		for _, c := range slice(d.Object, "spec", "template", "spec", "containers") {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if img, found := str(cm, "image"); found {
				if _, tag, cut := strings.Cut(img, ":"); cut && tag != "" {
					return tag
				}
			}
		}
	}
	return "unknown"
}

// platform decides between OpenShift and plain Kubernetes from whether the
// cluster *serves* the OpenShift API groups, not from whether those listings
// returned objects: security.openshift.io and route.openshift.io exist only on
// OpenShift, and an OpenShift cluster with zero routes is still OpenShift.
//
// Both answers are claims, so both need evidence. When neither read could be
// resolved -- denied, or the discovery that would have said "absent" failed --
// the answer is "unknown". Defaulting to "Kubernetes" there would print a fact
// nobody established onto every page of the report.
func platform(res Result) string {
	scc, routes := res.Get("scc"), res.Get("routes")

	// Served: discovery answered, and it answered yes.
	if scc.OK() || routes.OK() {
		return "OpenShift"
	}
	// Not served: discovery answered, and it answered no. Both must agree,
	// since a cluster may serve routes without SCC on old installs.
	if scc.Absent && routes.Absent {
		return "Kubernetes"
	}
	return "unknown"
}

func buildCluster(res Result, r *kdl.Report) {
	r.Cluster.KubernetesVersion = res.KubernetesVersion
	r.Cluster.Distribution = r.Platform
}

func buildPolicies(res Result, r *kdl.Report) {
	c := res.Get("policies")
	if !c.OK() {
		return
	}
	items := make([]kdl.PoliciesItem, 0, len(c.Items))
	dualExport := 0
	var sameProfileTwice []string

	for _, o := range c.Items {
		p := kdl.PoliciesItem{Name: name(o)}

		if f, ok := str(o.Object, "spec", "frequency"); ok {
			p.Frequency = &f
		}
		if pr, ok := str(o.Object, "spec", "presetRef", "name"); ok {
			p.PresetRef = &pr
		}

		actions := slice(o.Object, "spec", "actions")
		var exports []map[string]any
		for _, a := range actions {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			verb, _ := str(am, "action")
			if verb != "" {
				p.Actions = append(p.Actions, verb)
			}
			if verb == "export" {
				exports = append(exports, am)
			}
		}

		p.Selector = policySelector(o.Object)
		p.Scope = p.Selector.Scope()
		p.Retention = retention(mapAt(o.Object, "spec", "retention"))

		// Never read only the first export: since Kasten 9.0 a policy can carry
		// two, each with its own profile, frequency and retention.
		profilesSeen := map[string]int{}
		for _, e := range exports {
			ex := kdl.PolicyExport{}
			if v, ok := str(e, "exportParameters", "profile", "name"); ok {
				ex.Profile = &v
				profilesSeen[v]++
			}
			if v, ok := str(e, "exportParameters", "frequency"); ok {
				ex.Frequency = &v
			}
			if v, ok := boolAt(e, "exportParameters", "exportData", "enabled"); ok {
				ex.ExportData = &v
			}
			if v, ok := str(e, "exportParameters", "blockModeProfile", "name"); ok {
				ex.BlockModeProfile = &v
			}
			if rm := mapAt(e, "retention"); rm != nil {
				er := exportRetention(rm)
				ex.Retention = &er
			}
			p.Exports = append(p.Exports, ex)
		}
		if len(exports) > 1 {
			dualExport++
			for prof, n := range profilesSeen {
				if n > 1 {
					sameProfileTwice = append(sameProfileTwice, p.Name+" → "+prof)
				}
			}
		}
		// Backward-compatible first-export retention, matching KDL.sh.
		if len(p.Exports) > 0 && p.Exports[0].Retention != nil {
			p.ExportRetention = p.Exports[0].Retention
		}

		items = append(items, p)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	sort.Strings(sameProfileTwice)

	r.Policies.Items = items
	r.Policies.Count = len(items)
	for _, p := range items {
		if hasAction(p.Actions, "export") {
			r.Policies.WithExport++
		}
		if p.PresetRef != nil && *p.PresetRef != "" {
			r.Policies.WithPresets++
		}
	}
	r.Policies.AdditionalExport = &kdl.PoliciesAdditionalExport{
		Count:            dualExport,
		SameProfileTwice: sameProfileTwice,
	}
}

// policySelector round-trips the raw selector through the schema's own codec so
// the three mutually exclusive Kasten selector shapes are interpreted by the
// one tested implementation rather than by a second parser here.
func policySelector(obj map[string]any) kdl.PolicySelector {
	raw, found, err := unstructured.NestedFieldNoCopy(obj, "spec", "selector")
	if err != nil || !found || raw == nil {
		return kdl.PolicySelector{All: true}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return kdl.PolicySelector{All: true}
	}
	var sel kdl.PolicySelector
	if err := json.Unmarshal(encoded, &sel); err != nil {
		// An unmodelled selector shape must not be silently downgraded to a
		// catch-all: that would claim the policy protects everything. Leaving
		// every field zero makes Unrecognized() true, which is "scope unknown".
		return kdl.PolicySelector{Raw: encoded}
	}
	return sel
}

// retentionTier reads one retention key. hourly is included because it is a
// valid Kasten tier that no sample in this repository exercises -- omitting it
// would silently drop the retention of @hourly policies.
func retentionTier(m map[string]any, key string) int {
	if n, ok := toNumber(m[key]); ok {
		return int(n)
	}
	return 0
}

func retention(m map[string]any) kdl.PoliciesItemRetention {
	return kdl.PoliciesItemRetention{
		Hourly:  retentionTier(m, "hourly"),
		Daily:   retentionTier(m, "daily"),
		Weekly:  retentionTier(m, "weekly"),
		Monthly: retentionTier(m, "monthly"),
		Yearly:  retentionTier(m, "yearly"),
	}
}

func exportRetention(m map[string]any) kdl.PoliciesItemExportRetention {
	return kdl.PoliciesItemExportRetention{
		Hourly:  retentionTier(m, "hourly"),
		Daily:   retentionTier(m, "daily"),
		Weekly:  retentionTier(m, "weekly"),
		Monthly: retentionTier(m, "monthly"),
		Yearly:  retentionTier(m, "yearly"),
	}
}

func buildProfiles(res Result, r *kdl.Report) {
	c := res.Get("profiles")
	if !c.OK() {
		return
	}
	items := make([]kdl.ProfilesItem, 0, len(c.Items))
	immutable, vbr, hardened, vault := 0, 0, 0, 0

	for _, o := range c.Items {
		p := kdl.ProfilesItem{Name: name(o)}
		spec := mapAt(o.Object, "spec")

		// Deep scan, exactly as KDL.sh does and for its stated reason: the
		// nesting of these fields differs between the documented schema and
		// what live clusters return.
		if v, ok := deepFirstString(spec, "locationType"); ok {
			p.LocationType = v
		} else if v, ok := str(o.Object, "spec", "locationSpec", "type"); ok {
			p.LocationType = v
		}
		if v, ok := deepFirstString(spec, "objectStoreType"); ok {
			p.Backend = v
		} else if p.LocationType != "" {
			p.Backend = p.LocationType
		}
		if v, ok := deepFirstString(spec, "repoName"); ok {
			p.VBRRepoName = v
		}
		if v, ok := deepFirstString(spec, "repoType"); ok {
			p.VBRRepoType = v
		}
		if v, ok := deepFirstString(spec, "region"); ok {
			p.Region = v
		}
		if v, ok := deepFirstString(spec, "endpoint"); ok {
			p.Endpoint = v
		}

		// Any non-empty protectionPeriod counts, whatever its type: Kasten emits
		// seconds on some backends and a duration string on others.
		if deepFirstPresent(spec, "protectionPeriod") {
			immutable++
			if raw, ok := deepFirstAny(spec, "protectionPeriod"); ok && r.ImmutabilityDays == 0 {
				if days, parsed := protectionDays(raw); parsed {
					r.ImmutabilityDays = days
				}
			}
		}
		if strings.EqualFold(p.LocationType, "VBR") || p.VBRRepoName != "" {
			vbr++
		}
		if strings.Contains(strings.ToLower(p.Backend), "veeamvault") {
			vault++
		}
		// A hardened VBR repository carries immutability that no
		// protectionPeriod field reflects.
		if lower := strings.ToLower(p.VBRRepoType); strings.Contains(lower, "hardened") ||
			strings.Contains(lower, "objectlock") || strings.Contains(lower, "immutab") {
			hardened++
			t := true
			p.VBRImmutable = &t
		}

		items = append(items, p)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	r.Profiles.Items = items
	r.Profiles.Count = len(items)
	r.Profiles.ImmutableCount = immutable
	total := immutable + hardened
	r.Profiles.ImmutableCountTotal = &total
	r.Profiles.VBRCount = &vbr
	r.Profiles.VBRHardenedCount = &hardened
	r.Profiles.VeeamVaultCount = &vault
	r.ImmutabilitySignal = total > 0
}

func buildNamespaces(res Result, r *kdl.Report) {
	c := res.Get("namespaces")
	if !c.OK() {
		return
	}
	inv := make([]kdl.CoverageNamespacesInventoryItem, 0, len(c.Items))
	system := 0
	for _, o := range c.Items {
		item := kdl.CoverageNamespacesInventoryItem{
			Name:     name(o),
			Labels:   o.GetLabels(),
			IsSystem: isSystemNamespace(name(o)),
		}
		if item.IsSystem {
			system++
		}
		inv = append(inv, item)
	}
	sort.Slice(inv, func(i, j int) bool { return inv[i].Name < inv[j].Name })
	r.Coverage.NamespacesInventory = kdl.CoverageNamespacesInventory{
		Total:       len(inv),
		System:      system,
		Application: len(inv) - system,
		Items:       inv,
	}
}

// systemNamespacePattern is KDL.sh's SYSTEM_NS_PATTERNS, copied verbatim.
//
// It is an *unanchored, case-insensitive* alternation on purpose: "monitoring"
// must match "openshift-monitoring" and "my-monitoring" alike. An earlier
// version of this file carried three prefixes (kube-, openshift-, kasten-io)
// and a comment claiming it mirrored the shell. It did not: argocd,
// cert-manager, istio-system, velero, prometheus, grafana, rook-ceph, vault and
// a dozen more were classified as customer workloads, which inflates
// unprotectedNamespaces with a false gap for every platform component the
// customer never intended to back up -- and feeds each one to `kdl diff` as a
// fresh regression.
var systemNamespacePattern = regexp.MustCompile(`(?i)` + strings.Join([]string{
	"kube-system", "kube-public", "kube-node-lease", "openshift-", "openshift$",
	"default", "kasten-io", "calico-", "tigera-", "cattle-", "fleet-", "rancher-",
	"ingress-", "cert-manager", "istio-", "linkerd", "gatekeeper-", "falco",
	"velero", "longhorn-", "rook-", "portworx", "metallb", "nvidia-",
	"gpu-operator", "local-storage", "assisted-installer", "multicluster-",
	"hive", "rhacs-", "stackrox", "acs-", "sso", "keycloak", "vault",
	"external-secrets", "argocd", "gitops", "tekton-", "pipelines", "cicd",
	"monitoring", "logging", "tracing", "jaeger", "elastic", "splunk", "datadog",
	"dynatrace", "newrelic", "prometheus", "grafana", "alertmanager", "thanos",
}, "|"))

func isSystemNamespace(ns string) bool {
	return systemNamespacePattern.MatchString(ns)
}

func buildVirtualization(res Result, r *kdl.Report) {
	c := res.Get("virtualMachines")
	if c.Absent {
		// No KubeVirt on this cluster: nothing to report, and nothing wrong.
		return
	}
	if !c.OK() {
		return
	}
	vms := make([]kdl.VirtualizationVM, 0, len(c.Items))
	running, stopped := 0, 0
	for _, o := range c.Items {
		vm := kdl.VirtualizationVM{Name: name(o), Namespace: namespace(o)}
		vm.Status = strOr(o.Object, "Unknown", "status", "printableStatus")
		if ready, ok := boolAt(o.Object, "status", "ready"); ok {
			vm.Ready = ready
		}
		switch strings.ToLower(vm.Status) {
		case "running":
			running++
		case "stopped":
			stopped++
		}
		vms = append(vms, vm)
	}
	sort.Slice(vms, func(i, j int) bool {
		if vms[i].Namespace != vms[j].Namespace {
			return vms[i].Namespace < vms[j].Namespace
		}
		return vms[i].Name < vms[j].Name
	})
	r.Virtualization.VMs = vms
	r.Virtualization.TotalVMs = len(vms)
	r.Virtualization.VMsRunning = running
	r.Virtualization.VMsStopped = stopped
	r.Virtualization.Platform = "KubeVirt"
	if r.Platform == "OpenShift" {
		r.Virtualization.Platform = "OpenShift Virtualization"
	}
}

func buildStorage(res Result, r *kdl.Report) {
	if c := res.Get("storageClasses"); c.OK() {
		items := make([]kdl.StorageClassesItem, 0, len(c.Items))
		def := 0
		for _, o := range c.Items {
			sc := kdl.StorageClassesItem{
				Name:          name(o),
				Provisioner:   strOr(o.Object, "", "provisioner"),
				ReclaimPolicy: strOr(o.Object, "", "reclaimPolicy"),
				BindingMode:   strOr(o.Object, "", "volumeBindingMode"),
			}
			if v, ok := boolAt(o.Object, "allowVolumeExpansion"); ok {
				sc.Expandable = v
			}
			if o.GetAnnotations()["storageclass.kubernetes.io/is-default-class"] == "true" {
				sc.IsDefault = true
				def++
			}
			items = append(items, sc)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.StorageClasses.Items = items
		r.StorageClasses.Count = len(items)
		r.StorageClasses.DefaultCount = def
	}

	if c := res.Get("volumeSnapshotClasses"); c.OK() {
		items := make([]kdl.VolumeSnapshotClassesItem, 0, len(c.Items))
		def := 0
		for _, o := range c.Items {
			vsc := kdl.VolumeSnapshotClassesItem{
				Name:           name(o),
				Driver:         strOr(o.Object, "", "driver"),
				DeletionPolicy: strOr(o.Object, "", "deletionPolicy"),
			}
			if o.GetAnnotations()["snapshot.storage.kubernetes.io/is-default-class"] == "true" {
				vsc.IsDefault = true
				def++
			}
			items = append(items, vsc)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.VolumeSnapshotClasses.Items = items
		r.VolumeSnapshotClasses.Count = len(items)
		r.VolumeSnapshotClasses.DefaultCount = def
	}
}

func buildK10Resources(res Result, r *kdl.Report) {
	pods := res.Get("k10Pods")
	if pods.OK() {
		total, running, ready := 0, 0, 0
		withLimits, withoutLimits, containers := 0, 0, 0
		for _, o := range pods.Items {
			total++
			if phase, _ := str(o.Object, "status", "phase"); phase == "Running" {
				running++
			}
			if podReady(o) {
				ready++
			}
			for _, c := range slice(o.Object, "spec", "containers") {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				containers++
				if lim := mapAt(cm, "resources", "limits"); len(lim) > 0 {
					withLimits++
				} else {
					withoutLimits++
				}
			}
		}
		r.Health.Pods = kdl.HealthPods{Total: total, Running: running, Ready: ready}
		r.K10Resources.Summary.TotalPods = total
		r.K10Resources.Summary.TotalContainers = containers
		r.K10Resources.Summary.WithLimits = withLimits
		r.K10Resources.Summary.WithoutLimits = withoutLimits
	}

	deps := res.Get("k10Deployments")
	if deps.OK() {
		items := make([]kdl.K10ResourcesDeployment, 0, len(deps.Items))
		multi := 0
		for _, o := range deps.Items {
			d := kdl.K10ResourcesDeployment{Name: name(o)}
			if n, ok := intAt(o.Object, "spec", "replicas"); ok {
				d.Replicas = int(n)
			}
			if n, ok := intAt(o.Object, "status", "readyReplicas"); ok {
				d.Ready = int(n)
			}
			if n, ok := intAt(o.Object, "status", "availableReplicas"); ok {
				d.Available = int(n)
			}
			if d.Replicas > 1 {
				multi++
			}
			items = append(items, d)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.K10Resources.Deployments = items
		r.K10Resources.Summary.TotalDeployments = len(items)
		r.K10Resources.Summary.MultiReplicaDeployments = multi
	}
}

func podReady(o unstructured.Unstructured) bool {
	for _, c := range slice(o.Object, "status", "conditions") {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := str(cm, "type"); t == "Ready" {
			s, _ := str(cm, "status")
			return s == "True"
		}
	}
	return false
}

func buildRBACInventory(res Result, r *kdl.Report) {
	cr, crb := res.Get("clusterRoles"), res.Get("clusterRoleBindings")
	roles, rb := res.Get("roles"), res.Get("roleBindings")

	// fullyAccessible is a claim about what was read, so it must be false the
	// moment any of the four reads was refused. An inventory assembled from
	// three of four lists is incomplete, not complete-and-small.
	r.K10RBAC.Accessibility = kdl.K10RBACAccessibility{
		ClusterRoles:        cr.OK(),
		ClusterRoleBindings: crb.OK(),
		Roles:               roles.OK(),
		RoleBindings:        rb.OK(),
	}
	r.K10RBAC.Accessibility.FullyAccessible = cr.OK() && crb.OK() && roles.OK() && rb.OK()
	if !r.K10RBAC.Accessibility.FullyAccessible {
		r.K10RBAC.Accessibility.Note = "at least one RBAC listing was denied; the inventory below is incomplete, not empty"
	}

	if cr.OK() {
		items := make([]kdl.K10RBACClusterRolesItem, 0)
		for _, o := range cr.Items {
			if !isK10RBAC(name(o)) {
				continue
			}
			role := kdl.K10RBACClusterRolesItem{Name: name(o)}
			rules := slice(o.Object, "rules")
			role.RulesCount = len(rules)
			for _, ru := range rules {
				rm, ok := ru.(map[string]any)
				if !ok {
					continue
				}
				if containsStar(stringsFrom(slice(rm, "verbs"))) {
					role.VerbsAll = true
				}
				if containsStar(stringsFrom(slice(rm, "resources"))) {
					role.ResourcesAll = true
				}
			}
			items = append(items, role)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.K10RBAC.ClusterRoles = kdl.K10RBACClusterRoles{Count: len(items), Items: items}
	}

	if crb.OK() {
		subjects := map[string]kdl.K10RBACSubjectsItem{}
		count := 0
		for _, o := range crb.Items {
			roleRef, _ := str(o.Object, "roleRef", "name")
			if !isK10RBAC(name(o)) && !isK10RBAC(roleRef) {
				continue
			}
			count++
			for _, s := range slice(o.Object, "subjects") {
				sm, ok := s.(map[string]any)
				if !ok {
					continue
				}
				kind, _ := str(sm, "kind")
				nm, _ := str(sm, "name")
				if kind == "" || nm == "" {
					continue
				}
				item := kdl.K10RBACSubjectsItem{Kind: kind, Name: nm}
				if ns, ok := str(sm, "namespace"); ok {
					item.Namespace = &ns
				}
				subjects[kind+"/"+nm] = item
			}
		}
		r.K10RBAC.ClusterRoleBindings = kdl.K10RBACClusterRoleBindings{Count: count}

		keys := make([]string, 0, len(subjects))
		for k := range subjects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := subjects[k]
			r.K10RBAC.Subjects.Items = append(r.K10RBAC.Subjects.Items, s)
			switch s.Kind {
			case "User":
				r.K10RBAC.Subjects.Users++
			case "Group":
				r.K10RBAC.Subjects.Groups++
			case "ServiceAccount":
				r.K10RBAC.Subjects.ServiceAccounts++
			}
		}
		r.K10RBAC.Subjects.Total = len(r.K10RBAC.Subjects.Items)
	}

	if roles.OK() {
		r.K10RBAC.Roles = kdl.K10RBACRoles{Count: len(roles.Items)}
	}
	if rb.OK() {
		r.K10RBAC.RoleBindings = kdl.K10RBACRoleBindings{Count: len(rb.Items)}
	}
}

func isK10RBAC(n string) bool {
	lower := strings.ToLower(n)
	return strings.Contains(lower, "k10") || strings.Contains(lower, "kasten")
}

func containsStar(v []string) bool {
	for _, s := range v {
		if s == "*" {
			return true
		}
	}
	return false
}

func buildHealth(res Result, r *kdl.Report) {
	backups := countActions(res.Get("backupActions"))
	exports := countActions(res.Get("exportActions"))
	restores := countActions(res.Get("restoreActions"))

	r.Health.Backups.BackupActions = kdl.HealthBackupsBackupActions{
		Total: backups.total, Completed: backups.complete, Failed: backups.failed,
	}
	r.Health.Backups.ExportActions = kdl.HealthBackupsExportActions{
		Total: exports.total, Completed: exports.complete, Failed: exports.failed,
	}
	r.Health.Backups.RestoreActions = kdl.HealthBackupsRestoreActions{
		Total: restores.total, Completed: restores.complete, Failed: restores.failed,
		Running: restores.running, Other: restores.other,
	}

	// Restore actions are deliberately excluded from the success rate, matching
	// KDL.sh: a restore is an operator action, not a scheduled one, and folding
	// restore failures into backup health hides a backup problem.
	r.Health.Backups.TotalActions = backups.total + exports.total
	finished := backups.complete + backups.failed + exports.complete + exports.failed
	r.Health.Backups.FinishedActions = finished
	r.Health.Backups.CompletedActions = backups.complete + exports.complete
	r.Health.Backups.FailedActions = backups.failed + exports.failed
	r.Health.Backups.SuccessRateNote = "Covers Backup + Export finished actions only (Complete + Failed). Restore actions are reported separately and excluded."

	// "N/A" rather than "100%" when nothing finished: a rate over zero samples
	// is not a perfect score.
	if finished == 0 {
		r.Health.Backups.SuccessRate = "N/A"
	} else {
		r.Health.Backups.SuccessRate = fmt.Sprintf("%.1f", float64(r.Health.Backups.CompletedActions)*100/float64(finished))
	}

	if c := res.Get("restorePoints"); c.OK() {
		r.Health.Backups.RestorePoints = len(c.Items)
	}
}

type actionCounts struct{ total, complete, failed, running, other int }

// countActions classifies by the state vocabulary Kasten actually emits.
// "Complete" and "Failed" are terminal; everything else (Running, Pending,
// Cancelled) is counted separately rather than folded into failures, because a
// running action is not a failed one.
func countActions(c Collection) actionCounts {
	var out actionCounts
	if !c.OK() {
		return out
	}
	for _, o := range c.Items {
		out.total++
		state, _ := str(o.Object, "status", "state")
		switch state {
		case "Complete":
			out.complete++
		case "Failed":
			out.failed++
		case "Running":
			out.running++
		default:
			out.other++
		}
	}
	return out
}

func buildMisc(res Result, r *kdl.Report) {
	if c := res.Get("transformSets"); c.OK() {
		items := make([]kdl.TransformSetsItem, 0, len(c.Items))
		for _, o := range c.Items {
			items = append(items, kdl.TransformSetsItem{
				Name:           name(o),
				TransformCount: len(slice(o.Object, "spec", "transforms")),
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.TransformSets = kdl.TransformSets{Count: len(items), Items: items}
	}

	if c := res.Get("blueprints"); c.OK() {
		items := make([]kdl.KanisterBlueprintsItem, 0, len(c.Items))
		for _, o := range c.Items {
			bp := kdl.KanisterBlueprintsItem{Name: name(o), Namespace: namespace(o)}
			// Kanister puts actions at the root; some blueprints nest them under
			// spec. KDL.sh reads `(.actions // .spec.actions // {})`, so match it
			// rather than reporting half the blueprints as having no actions.
			actions := mapAt(o.Object, "actions")
			if len(actions) == 0 {
				actions = mapAt(o.Object, "spec", "actions")
			}
			bp.Actions = append(bp.Actions, sortedKeys(actions)...)
			items = append(items, bp)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.Kanister.Blueprints = kdl.KanisterBlueprints{Count: len(items), Items: items}
	}
	if c := res.Get("blueprintBindings"); c.OK() {
		r.Kanister.Bindings.Count = len(c.Items)
	}

	if c := res.Get("policyPresets"); c.OK() {
		items := make([]kdl.PolicyPresetsItem, 0, len(c.Items))
		for _, o := range c.Items {
			items = append(items, kdl.PolicyPresetsItem{Name: name(o)})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		r.PolicyPresets = kdl.PolicyPresets{Count: len(items), Items: items}
	}

	// Import policies and export-less policies are derived from the policy list
	// that is already built, so they cost nothing extra.
	//
	// System policies are excluded, as KDL.sh does by computing these from its
	// app-policy list: K10's own DR policy carries no export action, so counting
	// it would put a Kasten-installed policy in every customer's "no off-site
	// copy" list.
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) {
			continue
		}
		if hasAction(p.Actions, "import") {
			freq := "manual"
			if p.Frequency != nil {
				freq = *p.Frequency
			}
			r.ImportPolicies.Items = append(r.ImportPolicies.Items, kdl.ImportPoliciesItem{
				Name: p.Name, Frequency: freq,
			})
		}
		if !hasAction(p.Actions, "export") {
			r.PoliciesWithoutExport.Items = append(r.PoliciesWithoutExport.Items, p.Name)
		}
	}
	r.ImportPolicies.Count = len(r.ImportPolicies.Items)
	r.PoliciesWithoutExport.Count = len(r.PoliciesWithoutExport.Items)
}

// buildCoverage resolves policy selectors against the namespace inventory.
//
// It runs only when both reads succeeded: computing "unprotected namespaces"
// from a denied policy listing would report every namespace in the cluster as
// unprotected, which is the most alarming possible way to render a permissions
// problem.
func buildCoverage(res Result, r *kdl.Report) {
	if !res.Get("policies").OK() || !res.Get("namespaces").OK() {
		r.Coverage.Note = "not computed: the policy or namespace listing was not readable"
		return
	}

	appNamespaces := make([]string, 0)
	for _, ns := range r.Coverage.NamespacesInventory.Items {
		if !ns.IsSystem {
			appNamespaces = append(appNamespaces, ns.Name)
		}
	}

	protected := map[string]bool{}
	catchAll := 0
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) || !hasAction(p.Actions, "backup") {
			continue
		}
		if p.Selector.All {
			catchAll++
			for _, ns := range appNamespaces {
				protected[ns] = true
			}
			continue
		}
		// Excluded patterns must be honoured: the catch-all-with-exceptions
		// shape would otherwise mark deliberately excluded namespaces protected.
		excluded := p.Selector.ExcludedNamespacePatterns()
		for _, pattern := range p.Selector.NamespacePatterns() {
			for _, ns := range appNamespaces {
				if kdl.GlobMatch(pattern, ns) && !kdl.GlobAny(excluded, ns) {
					protected[ns] = true
				}
			}
		}

		// matchLabels on a NAMESPACE-scoped policy selects namespaces by label.
		// Ignoring it reported those namespaces as unprotected -- the exact
		// false-positive gap KDL.sh fixed and labelled (#11).
		//
		// The scope guard is not optional: on a VM-scoped policy the very same
		// matchLabels filters VMs, and resolving it against the namespace
		// inventory would credit a whole namespace to a policy that protects a
		// handful of VMs inside it.
		if len(p.Selector.MatchLabels) > 0 && p.EffectiveScope() == kdl.ScopeNamespace {
			for _, ns := range r.Coverage.NamespacesInventory.Items {
				if ns.IsSystem || !labelsMatch(p.Selector.MatchLabels, ns.Labels) {
					continue
				}
				if !kdl.GlobAny(excluded, ns.Name) {
					protected[ns.Name] = true
				}
			}
		}
	}

	var unprotected []string
	for _, ns := range appNamespaces {
		if !protected[ns] {
			unprotected = append(unprotected, ns)
		}
	}
	sort.Strings(unprotected)

	r.Coverage.PoliciesTargetingAllNamespaces = catchAll
	r.Coverage.HasCatchallPolicy = catchAll > 0
	r.Coverage.UnprotectedNamespaces = kdl.CoverageUnprotectedNamespaces{
		Count: len(unprotected), Items: unprotected,
	}
	r.Coverage.Note = "Based on app policies only (excludes DR/report system policies); selector-based, not run-history based."
}

func buildPolicyAnalysis(res Result, r *kdl.Report) {
	if !res.Get("policies").OK() || !res.Get("namespaces").OK() {
		r.PolicyAnalysis.Note = "not computed: the policy or namespace listing was not readable"
		return
	}

	existing := map[string]bool{}
	for _, ns := range r.Coverage.NamespacesInventory.Items {
		existing[ns.Name] = true
	}

	analysed := 0
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) {
			continue
		}
		analysed++

		if p.Selector.All {
			continue
		}
		patterns := p.Selector.NamespacePatterns()
		var missing []string
		effective := 0
		for _, pattern := range patterns {
			matched := false
			for ns := range existing {
				if kdl.GlobMatch(pattern, ns) {
					matched = true
					effective++
				}
			}
			// Only a literal pattern can be called a non-existing reference: an
			// unmatched glob is an empty match, not a typo'd namespace name.
			if !matched && !strings.ContainsAny(pattern, "*?") {
				missing = append(missing, pattern)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			r.PolicyAnalysis.PoliciesWithNonExistingReferences = append(
				r.PolicyAnalysis.PoliciesWithNonExistingReferences,
				kdl.PolicyAnalysisPoliciesWithNonExistingReference{
					Name: p.Name, NonExistingReferences: missing,
				})
		}
		if effective == 0 && len(patterns) > 0 {
			r.PolicyAnalysis.EmptyPolicies = append(r.PolicyAnalysis.EmptyPolicies,
				kdl.PolicyAnalysisEmptyPolicy{
					Name:           p.Name,
					SelectorKind:   selectorKind(p.Selector),
					TargetedCount:  len(patterns),
					EffectiveCount: 0,
				})
		}
	}

	r.PolicyAnalysis.Summary = kdl.PolicyAnalysisSummary{
		TotalPolicies:          analysed,
		EmptyCount:             len(r.PolicyAnalysis.EmptyPolicies),
		WithNonExistingNSCount: len(r.PolicyAnalysis.PoliciesWithNonExistingReferences),
	}
	r.PolicyAnalysis.Note = "App policies only (system DR/reports policies excluded). Redundancy analysis is not computed by the Go collector yet."
}

// labelsMatch reports whether every required label is present with the required
// value, which is Kubernetes matchLabels semantics (AND, not OR).
func labelsMatch(required, actual map[string]string) bool {
	for k, v := range required {
		if actual[k] != v {
			return false
		}
	}
	return len(required) > 0
}

// selectorKind names the selector shape using KDL's own vocabulary. "catchall"
// is the word the emitter writes; "all" was invented here, and an invented word
// is how a real value ends up misclassified as unknown.
func selectorKind(s kdl.PolicySelector) string {
	switch {
	case s.All:
		return "catchall"
	case len(s.MatchExpressions) > 0:
		return "matchExpressions"
	case len(s.MatchNames) > 0:
		return "matchNames"
	case len(s.MatchLabels) > 0:
		return "matchLabels"
	}
	return "unknown"
}

// isSystemPolicy matches the policies K10 installs for itself, which KDL.sh
// excludes from coverage and analysis so a customer's posture is not judged on
// Kasten's own housekeeping.
//
// Matched exactly, not by prefix. KDL.sh anchors these names and says why --
// "be specific to avoid excluding user policies with 'report' in name" -- and a
// prefix match silently drops a customer policy called
// k10-disaster-recovery-test from both coverage and policy analysis.
func isSystemPolicy(n string) bool {
	switch n {
	case "k10-disaster-recovery-policy", "k10-system-reports-policy", "k10-system-reports":
		return true
	}
	return false
}

func hasAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}
