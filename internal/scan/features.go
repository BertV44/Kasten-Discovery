package scan

// Whether two K10 features are actually working, as opposed to installed.
//
// Both are read from collections the plan already fetches, and both answer the
// same shape of question: the presence of a configuration object is not evidence
// that the thing it configures does anything.

import (
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
)

// drPolicyName is the policy K10 installs to protect its own catalog. It is not
// a policy a customer creates, and its name is fixed by K10.
const drPolicyName = "k10-disaster-recovery-policy"

// naValue is the string KDL.sh writes where a field does not apply. It is a
// literal in the report, so it is spelled once here rather than at each use.
const naValue = "N/A"

// DR verdicts, as KDL.sh spells them. The renderer and kdl diff both match on
// these exact strings.
const (
	drEnabled    = "ENABLED"
	drNotHealthy = "CONFIGURED_NOT_HEALTHY"
	drNotEnabled = "NOT_ENABLED"
)

// buildDisasterRecovery reports whether K10 can restore itself.
//
// The verdict comes from the last DR run, not from the presence of the DR
// policy. An installed policy that has never completed protects nothing, and
// "enabled" over that is the most expensive false reassurance the report can
// give: the customer finds out at the moment they have lost the cluster and are
// trying to get the catalog back.
func buildDisasterRecovery(res Result, r *kdl.Report, now time.Time) {
	var drPolicy map[string]any
	for _, o := range res.Items("policies") {
		if name(o) == drPolicyName {
			drPolicy = o.Object
			break
		}
	}

	if drPolicy == nil {
		r.DisasterRecovery = kdl.DisasterRecovery{
			Enabled:      false,
			Status:       drNotEnabled,
			Mode:         "Not Configured",
			Frequency:    naValue,
			Profile:      naValue,
			LastRunState: "None",
		}
		return
	}

	dr := kdl.DisasterRecovery{
		Enabled:      true,
		Frequency:    strOr(drPolicy, naValue, "spec", "frequency"),
		Profile:      drProfile(drPolicy),
		LastRunState: "None",
	}

	// kdrSnapshotConfiguration is what distinguishes Quick DR from the legacy
	// full-catalog-export shape. Its absence is the legacy shape, not a fault.
	if cfg := mapAt(drPolicy, "spec", "kdrSnapshotConfiguration"); cfg != nil {
		dr.LocalCatalogSnapshot, _ = boolAt(cfg, "enabled")
		dr.ExportCatalogSnapshot, _ = boolAt(cfg, "exportData", "enabled")
		switch {
		case dr.LocalCatalogSnapshot:
			dr.Mode = "Quick DR (Local Catalog Snapshot)"
		case dr.ExportCatalogSnapshot:
			dr.Mode = "Quick DR (Exported Catalog Snapshot)"
		default:
			dr.Mode = "Quick DR (No Catalog Snapshot)"
		}
	} else {
		dr.Mode = "Legacy DR (Full Catalog Exports)"
	}

	// A DR export target is configured outside the policy, in the DR secret, so
	// a perfectly healthy DR reads as having no profile. Saying why keeps an
	// operator from hunting for a broken reference that was never there.
	if dr.Profile == naValue && dr.Mode == "Quick DR (No Catalog Snapshot)" {
		dr.Profile = naValue + " (export target set outside policy)"
	}

	dr.Status, dr.LastRunState, dr.LastSuccessfulRun = drHealth(res, now)
	r.DisasterRecovery = dr
}

// drProfile resolves the DR location profile from whichever action carries it.
// Modern DR backs the catalog up through a backup action; other shapes use an
// export action. Reading only exportParameters showed a configured DR as having
// no profile.
func drProfile(drPolicy map[string]any) string {
	for _, path := range [][]string{
		{"exportParameters", "profile", "name"},
		{"backupParameters", "profile", "name"},
	} {
		for _, a := range slice(drPolicy, "spec", "actions") {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if v, found := str(am, path...); found && v != "" {
				return v
			}
		}
	}
	return naValue
}

// drHealth derives the verdict from the DR policy's run history.
//
// The verdict is deliberately not gated on the DR mode or on resolving an inline
// export profile: Quick and Legacy DR both export the catalog by design once the
// policy runs successfully, and "Quick DR (No Catalog Snapshot)" does not mean
// no export. Gating on those signals reported working clusters as incomplete.
func drHealth(res Result, now time.Time) (status, lastState, lastSuccess string) {
	var runs []run
	for _, o := range res.Items("runActions") {
		if subject, ok := str(o.Object, "spec", "subject", "name"); !ok || subject != drPolicyName {
			continue
		}
		runs = append(runs, run{
			timestamp: creationTimestamp(o),
			state:     strOr(o.Object, "Unknown", "status", "state"),
		})
	}

	// Two separate "newest": the last run of any state drives lastRunState, and
	// the last *successful* one drives staleness. Collapsing them would let a
	// failed run erase the record of the successful one before it.
	lastState = "None"
	newest := ""
	for _, run := range runs {
		if run.timestamp >= newest {
			newest, lastState = run.timestamp, run.state
		}
		if run.complete() && run.timestamp > lastSuccess {
			lastSuccess = run.timestamp
		}
	}

	switch {
	case lastState == stateFailed:
		return drNotHealthy, lastState, lastSuccess
	case lastSuccess == "":
		// Never succeeded. A DR that has only ever been scheduled is not DR.
		return drNotHealthy, lastState, lastSuccess
	default:
		// Staleness is computed, not defaulted. KDL.sh notes the trap in its own
		// implementation: `.successStale // true` treats a healthy false as
		// absent and flips it, marking every non-stale DR stale.
		days, ok := ageDays(lastSuccess, now)
		if !ok || days > staleBackupThresholdDays {
			return drNotHealthy, lastState, lastSuccess
		}
		return drEnabled, lastState, lastSuccess
	}
}

// buildMonitoring reports whether the Prometheus K10 ships with is running.
//
// Scoped to the K10 namespace and to the K10 chart's own pod labels, which
// matters more than it sounds: a cluster-wide search for Prometheus matches
// OpenShift's cluster monitoring on every OpenShift cluster in existence, so the
// check returned true regardless of whether K10 monitoring was enabled at all.
func buildMonitoring(res Result, r *kdl.Report) {
	for _, o := range res.Items("k10Pods") {
		if phase, _ := str(o.Object, "status", "phase"); phase != "Running" {
			continue
		}
		labels := o.GetLabels()
		if labels["app"] == "prometheus" {
			r.Monitoring.Prometheus = true
			return
		}
		// The chart label scheme changed; both are current on clusters in the
		// field, so both are matched.
		if labels["app.kubernetes.io/name"] == "prometheus" &&
			labels["app.kubernetes.io/instance"] == "k10" {
			r.Monitoring.Prometheus = true
			return
		}
	}
}

// mcNamespace is the namespace a multi-cluster primary keeps its joined-cluster
// records in, and its existence is what makes a cluster a primary.
const mcNamespace = "kasten-io-mc"

// mcJoinConfigMap is what a secondary carries instead: the record of which
// primary it answers to.
const mcJoinConfigMap = "mc-join-config"

// buildMultiCluster reports this cluster's place in a multi-cluster setup.
//
// It matters to every other section: on a secondary, policies and profiles are
// pushed from the primary, so a finding about a policy nobody here created is
// not something an operator on this cluster can act on.
func buildMultiCluster(res Result, r *kdl.Report) {
	for _, ns := range r.Coverage.NamespacesInventory.Items {
		if ns.Name != mcNamespace {
			continue
		}
		r.MultiCluster.Role = "primary"
		// Counted from the cluster records themselves. An absent CRD leaves this
		// at zero, which on a primary means the records could not be read rather
		// than that no cluster has joined -- mcClusters is named in
		// sectionInputs for exactly that reason.
		r.MultiCluster.ClusterCount = len(res.Items("mcClusters"))
		return
	}

	for _, cm := range res.Items("k10ConfigMaps") {
		if name(cm) != mcJoinConfigMap {
			continue
		}
		r.MultiCluster.Role = "secondary"
		data := mapAt(cm.Object, "data")
		// Both spellings are in the field: the key changed between releases and
		// reading only one reports a joined secondary as having no primary.
		r.MultiCluster.PrimaryName = optional(firstNonEmpty(data, "primaryClusterName", "primary"))
		r.MultiCluster.ClusterID = optional(firstNonEmpty(data, "clusterId", "clusterID"))
		return
	}

	r.MultiCluster.Role = "none"
}

// firstNonEmpty returns the first key that carries a value, for fields whose
// name changed between Kasten releases.
func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
