package scan

// The two sections that are judgements rather than readings: the 16
// best-practice checks and the 8-pillar ransomware readiness score.
//
// They were the last sections withheld, and the reason was never that they are
// hard -- both are a page of thresholds -- but that a verdict computed over a
// partially collected cluster is worse than an absent one. Every check here is
// therefore written to produce three answers, not two, and the third is
// NOT_ASSESSED: "the input this needs was never read". The renderer paints that
// neither green nor red, and it is counted apart from both passes and failures.
//
// The failure mode this guards against is specific and was observed: leave a
// check's status empty and the renderer does not recognise the value, so the
// check fails, so the two critical checks paint "✗ CRITICAL" and the report's
// banner reads "2 Critical" -- on a cluster where nobody looked at either.

import (
	"sort"
	"strings"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
)

// Statuses the checks emit. They are KDL.sh's exact words: the renderer maps
// each to a badge and treats anything it does not recognise as a failure, so an
// invented value here is a check that silently fails on every cluster.
const (
	statusConfigured    = "CONFIGURED"
	statusNotConfigured = "NOT_CONFIGURED"
	statusEnabled       = "ENABLED"
	statusNotEnabled    = "NOT_ENABLED"
	statusInUse         = "IN_USE"
	statusNotUsed       = "NOT_USED"
	statusComplete      = "COMPLETE"
	statusPartial       = "PARTIAL"
	statusGapsDetected  = "GAPS_DETECTED"
	statusOK            = "OK"
	statusWarn          = "WARN"
	statusNA            = "N/A"
)

// buildBestPractices fills the 16 checks.
//
// Each one is derived from a section this collector populates, and each one asks
// first whether that section was populated at all. The report declares its
// uncollected sections, so this consults that declaration rather than guessing
// from zero values -- a count of zero is the answer for a healthy cluster and for
// an unread one, and the whole point of the exercise is to keep those apart.
func buildBestPractices(res Result, r *kdl.Report) {
	bp := &r.BestPractices
	uncollected := func(sections ...string) bool {
		for _, s := range sections {
			if r.NotCollected(s) {
				return true
			}
		}
		return false
	}

	// Critical: DR carries the effective verdict rather than a pass/fail of its
	// own, so the check and the DR section can never disagree.
	if uncollected("disasterRecovery") {
		bp.DisasterRecovery = kdl.StatusNotAssessed
	} else {
		bp.DisasterRecovery = r.DisasterRecovery.Status
	}

	// Critical: an unauthenticated dashboard is a restore capability open to
	// anyone who can reach it. "unknown" is the collector saying neither config
	// source was readable, and it must not read as a failure.
	switch method := r.K10Configuration.Security.Authentication.Method; {
	case method == "" || method == "unknown" || uncollected("k10Configuration"):
		bp.Authentication = kdl.StatusNotAssessed
	case method != "none":
		bp.Authentication = statusConfigured
	default:
		bp.Authentication = statusNotConfigured
	}

	// Immutability counts protectionPeriod profiles and hardened VBR
	// repositories together: the latter carry immutability without ever exposing
	// a protectionPeriod, and counting only the first reported hardened
	// repositories as mutable.
	if !res.Get("profiles").OK() {
		bp.Immutability = kdl.StatusNotAssessed
	} else if immutableTotal(r) > 0 {
		bp.Immutability = statusEnabled
	} else {
		bp.Immutability = statusNotConfigured
	}

	if uncollected("k10Configuration") {
		bp.Encryption = kdl.StatusNotAssessed
		bp.AuditLogging = kdl.StatusNotAssessed
	} else {
		bp.Encryption = configuredIf(r.K10Configuration.Security.Encryption.Provider != "none" &&
			r.K10Configuration.Security.Encryption.Provider != "")
		bp.AuditLogging = enabledIf(r.K10Configuration.Security.AuditLogging.Enabled)
	}

	// Namespace protection reads the actionable count, not the raw one: a
	// namespace deliberately excluded through excludedApps or a policy exception
	// is not a gap, and counting it as one buries the ones that are.
	switch {
	case !res.Get("namespaces").OK() || !res.Get("policies").OK():
		bp.NamespaceProtection = kdl.StatusNotAssessed
	case r.Coverage.HasCatchallPolicy || actionableGaps(r) == 0:
		bp.NamespaceProtection = statusComplete
	default:
		bp.NamespaceProtection = statusGapsDetected
	}

	bp.VMProtection = vmProtectionStatus(res, r)
	bp.VMSnapshotConsistency = vmConsistencyStatus(res, r)

	if c := res.Get("policyPresets"); !c.OK() && !c.Absent {
		bp.PolicyPresets = kdl.StatusNotAssessed
	} else if r.PolicyPresets.Count > 0 {
		bp.PolicyPresets = statusInUse
	} else {
		bp.PolicyPresets = statusNotUsed
	}

	if uncollected("monitoring") {
		bp.Monitoring = kdl.StatusNotAssessed
	} else {
		bp.Monitoring = enabledIf(r.Monitoring.Prometheus)
	}

	// Resource limits: a K10 pod without limits can be evicted mid-backup, and
	// "some containers have limits" is a real state distinct from both.
	summary := r.K10Resources.Summary
	switch {
	case !res.Get("k10Pods").OK():
		bp.ResourceLimits = kdl.StatusNotAssessed
	case summary.WithoutLimits == 0 && summary.WithLimits > 0:
		bp.ResourceLimits = statusConfigured
	default:
		bp.ResourceLimits = statusPartial
	}

	// The three retention checks and the two policy-shape checks all come from
	// the policy listing.
	if uncollected("retentionAnalysis") {
		bp.SnapshotRetentionHigh = kdl.StatusNotAssessed
		bp.SnapshotRetentionZero = kdl.StatusNotAssessed
		bp.ExportRetentionExplicit = kdl.StatusNotAssessed
	} else {
		ra := r.RetentionAnalysis
		bp.SnapshotRetentionHigh = warnIf(ra.SnapshotRetentionHigh.Count > 0)
		bp.SnapshotRetentionZero = warnIf(ra.SnapshotRetentionZero.Count > 0)
		bp.ExportRetentionExplicit = warnIf(ra.ExportWithoutExplicitRetention.Count > 0)
	}

	if !res.Get("policies").OK() {
		bp.ClusterScopedResources = kdl.StatusNotAssessed
		bp.PoliciesWithoutExport = kdl.StatusNotAssessed
	} else {
		protected := clusterScopedProtected(res, r)
		bp.ClusterScopedResourcesProtected = protected
		bp.ClusterScopedResources = configuredIf(protected)
		bp.PoliciesWithoutExport = warnIf(r.PoliciesWithoutExport.Count > 0)
	}
}

func configuredIf(ok bool) string {
	if ok {
		return statusConfigured
	}
	return statusNotConfigured
}

func enabledIf(ok bool) string {
	if ok {
		return statusEnabled
	}
	return statusNotEnabled
}

// warnIf is the polarity the three retention checks and the export check use:
// the finding is the presence of something, so OK is the absence of it.
func warnIf(found bool) string {
	if found {
		return statusWarn
	}
	return statusOK
}

// immutableTotal is the profile count that carries immutability by any
// mechanism. ImmutableCountTotal is the 2.2.0 field that includes hardened VBR
// repositories; it is a pointer, and its absence is an older report rather than
// zero.
func immutableTotal(r *kdl.Report) int {
	if r.Profiles.ImmutableCountTotal != nil {
		return *r.Profiles.ImmutableCountTotal
	}
	return r.Profiles.ImmutableCount
}

// actionableGaps is the unprotected count with the deliberate exclusions
// subtracted, falling back to the raw count when the breakdown is absent. The
// fallback direction matters: without it a missing breakdown would read as zero
// gaps, which is the reassuring answer.
func actionableGaps(r *kdl.Report) int {
	if bd := r.Coverage.UnprotectedBreakdown; bd != nil && !r.NotCollected("coverage.unprotectedBreakdown") {
		return bd.Actionable
	}
	return r.Coverage.UnprotectedNamespaces.Count
}

// vmProtectionStatus grades VM coverage, and reports N/A on a cluster with no
// VMs -- an inapplicable check must not read as a passed one either.
func vmProtectionStatus(res Result, r *kdl.Report) string {
	c := res.Get("virtualMachines")
	// Order matters here. A denied VM listing also leaves totalVMs at zero, and
	// answering N/A first would report "no VMs on this cluster" -- a claim about
	// virtualization -- from a read that was refused.
	if (!c.OK() && !c.Absent) || !res.Get("policies").OK() {
		return kdl.StatusNotAssessed
	}
	if c.Absent || r.Virtualization.TotalVMs == 0 {
		return statusNA
	}
	p := r.Virtualization.Protection
	switch {
	case p.UnprotectedVMs == 0:
		return statusComplete
	case p.ProtectedVMs > 0:
		return statusPartial
	default:
		return statusNotConfigured
	}
}

// vmConsistencyStatus flags crash-consistent VM restore points. Kasten falls
// back to a crash-consistent snapshot silently when the guest freeze is
// unavailable, so nothing else in the report mentions it.
func vmConsistencyStatus(res Result, r *kdl.Report) string {
	// Same trap as vmProtectionStatus: the consistency counts are absent both
	// when there are no VM restore points and when the restore-point read failed.
	if c := res.Get("restorePoints"); !c.OK() && !c.Absent && r.Virtualization.TotalVMs > 0 {
		return kdl.StatusNotAssessed
	}
	vc := r.Virtualization.VMRestorePointConsistency
	if vc == nil || vc.Total == 0 {
		return statusNA
	}
	if vc.CrashConsistent > 0 {
		return statusWarn
	}
	// Restore points whose consistency was never recorded are not evidence of a
	// quiesced guest, so they hold the check back rather than passing it.
	if vc.Unknown > 0 && vc.ApplicationConsistent == 0 {
		return kdl.StatusNotAssessed
	}
	return statusOK
}

// clusterScopedProtected reports whether any policy backs up cluster-scoped
// resources. Without one, a restore rebuilds the workloads but not the CRDs,
// ClusterRoles or webhooks they depend on.
func clusterScopedProtected(res Result, r *kdl.Report) bool {
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) {
			continue
		}
		if p.Selector.MatchLabels["k10.kasten.io/appType"] == "cluster" {
			return true
		}
	}
	// includeClusterResources sits on the backup action, which the typed policy
	// does not carry, so it is read from the raw objects.
	for _, o := range res.Items("policies") {
		if isSystemPolicy(name(o)) {
			continue
		}
		for _, a := range slice(o.Object, "spec", "actions") {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if v, found := boolAt(am, "backupParameters", "includeClusterResources"); found && v {
				return true
			}
		}
	}
	return false
}

// Ransomware pillar weights, validated with the TAM team. They are named
// constants because they are the report's most quoted numbers -- the score goes
// in front of a CISO -- and a silent change to one would change every grade.
const (
	pillarImmutabilityMax     = 20
	pillarOffClusterExportMax = 15
	pillarAuthenticationMax   = 15
	pillarDisasterRecoveryMax = 15
	pillarAuditLoggingMax     = 10
	pillarKMSEncryptionMax    = 10
	pillarNetworkPoliciesMax  = 10
	pillarTLSVerificationMax  = 5
)

// buildRansomwareReadiness synthesises the eight pillars into a score and a
// grade.
//
// Every pillar is all-or-nothing, and every one is awarded on evidence rather
// than on configuration being present. The DR pillar is the clearest case: it
// pays only when DR is effectively healthy, never merely configured, because a
// 15/15 next to a CONFIGURED_NOT_HEALTHY verdict is a contradiction the reader
// would resolve in the reassuring direction.
//
// An unreadable input scores zero, which is the one place this section cannot be
// honest on its own -- a zero pillar looks like a failed one. That is why the
// section is declared unpopulated whenever any pillar's input was not collected:
// a grade is a single number and there is no room in it for "partly unknown".
func buildRansomwareReadiness(res Result, r *kdl.Report) {
	sec := r.K10Configuration.Security
	tlsSkipped := profilesSkippingTLS(res)

	immutability := immutableTotal(r) > 0 && r.ImmutabilitySignal
	offCluster := r.Policies.WithExport > 0
	auth := sec.Authentication.Method != "none" && sec.Authentication.Method != "" &&
		sec.Authentication.Method != "unknown"
	dr := r.DisasterRecovery.Status == drEnabled
	audit := sec.AuditLogging.Enabled
	kms := sec.Encryption.Provider != "none" && sec.Encryption.Provider != ""
	netpol := sec.NetworkPolicies
	tlsOK := len(tlsSkipped) == 0

	pillars := kdl.RansomwareReadinessPillars{
		Immutability: kdl.RansomwareReadinessPillarsImmutability{
			Score: award(immutability, pillarImmutabilityMax), Max: pillarImmutabilityMax, Evidence: immutability},
		OffClusterExport: kdl.RansomwareReadinessPillarsOffClusterExport{
			Score: award(offCluster, pillarOffClusterExportMax), Max: pillarOffClusterExportMax, Evidence: offCluster},
		Authentication: kdl.RansomwareReadinessPillarsAuthentication{
			Score: award(auth, pillarAuthenticationMax), Max: pillarAuthenticationMax, Evidence: auth},
		DisasterRecovery: kdl.RansomwareReadinessPillarsDisasterRecovery{
			Score: award(dr, pillarDisasterRecoveryMax), Max: pillarDisasterRecoveryMax, Evidence: dr},
		AuditLogging: kdl.RansomwareReadinessPillarsAuditLogging{
			Score: award(audit, pillarAuditLoggingMax), Max: pillarAuditLoggingMax, Evidence: audit},
		KMSEncryption: kdl.RansomwareReadinessPillarsKMSEncryption{
			Score: award(kms, pillarKMSEncryptionMax), Max: pillarKMSEncryptionMax, Evidence: kms},
		NetworkPolicies: kdl.RansomwareReadinessPillarsNetworkPolicies{
			Score: award(netpol, pillarNetworkPoliciesMax), Max: pillarNetworkPoliciesMax, Evidence: netpol},
		TLSVerification: kdl.RansomwareReadinessPillarsTLSVerification{
			Score: award(tlsOK, pillarTLSVerificationMax), Max: pillarTLSVerificationMax,
			Evidence: tlsOK, ProfilesSkippingTLS: tlsSkipped},
	}

	total := pillars.Immutability.Score + pillars.OffClusterExport.Score +
		pillars.Authentication.Score + pillars.DisasterRecovery.Score +
		pillars.AuditLogging.Score + pillars.KMSEncryption.Score +
		pillars.NetworkPolicies.Score + pillars.TLSVerification.Score
	max := pillarImmutabilityMax + pillarOffClusterExportMax + pillarAuthenticationMax +
		pillarDisasterRecoveryMax + pillarAuditLoggingMax + pillarKMSEncryptionMax +
		pillarNetworkPoliciesMax + pillarTLSVerificationMax

	r.RansomwareReadiness = kdl.RansomwareReadiness{
		Grade:      grade(total),
		Score:      total,
		MaxScore:   max,
		BiggestGap: biggestGap(pillars),
		Pillars:    pillars,
		GradeThresholds: kdl.RansomwareReadinessGradeThresholds{
			A: ">=85", B: "70-84", C: "55-69", D: "40-54", F: "<40",
		},
		Note: "Synthesis of 8 security pillars. Score and grade are intended for " +
			"executive/CISO communication. Pillar weighting validated empirically; " +
			"review against your org threat model.",
	}
}

func award(evidence bool, max int) int {
	if evidence {
		return max
	}
	return 0
}

// grade maps the score to a letter. The thresholds are empirical and are emitted
// alongside the grade, so a reader can see what a B means without this code.
func grade(score int) string {
	switch {
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// biggestGap names the pillar losing the most points, which is the section's
// only actionable output: a grade tells a CISO where they stand, this tells an
// engineer what to do on Monday.
func biggestGap(p kdl.RansomwareReadinessPillars) kdl.RansomwareReadinessBiggestGap {
	candidates := []kdl.RansomwareReadinessBiggestGap{
		{Pillar: "Immutability", PointsLost: p.Immutability.Max - p.Immutability.Score},
		{Pillar: "Off-cluster export", PointsLost: p.OffClusterExport.Max - p.OffClusterExport.Score},
		{Pillar: "Authentication", PointsLost: p.Authentication.Max - p.Authentication.Score},
		{Pillar: "Disaster Recovery", PointsLost: p.DisasterRecovery.Max - p.DisasterRecovery.Score},
		{Pillar: "Audit logging", PointsLost: p.AuditLogging.Max - p.AuditLogging.Score},
		{Pillar: "KMS encryption", PointsLost: p.KMSEncryption.Max - p.KMSEncryption.Score},
		{Pillar: "Network policies", PointsLost: p.NetworkPolicies.Max - p.NetworkPolicies.Score},
		{Pillar: "TLS verification", PointsLost: p.TLSVerification.Max - p.TLSVerification.Score},
	}
	// First maximum wins, and the list is in descending weight order, so a tie
	// resolves to the heavier pillar -- which is the one worth fixing first.
	best := kdl.RansomwareReadinessBiggestGap{}
	for _, c := range candidates {
		if c.PointsLost > best.PointsLost {
			best = c
		}
	}
	return best
}

// profilesSkippingTLS finds location profiles with certificate verification
// disabled.
//
// The search is a bounded deep scan over the profile spec rather than a list of
// known paths, and that is not tidiness: KDL.sh looked only under
// locationSpec.objectStore and infrastoreBlobStore, so a Veeam Backup &
// Replication profile -- where the flag lives under locationSpec.vbr, and which
// Kasten 9.0 makes a first-class export target -- always reported TLS
// verification as enabled. That handed a free 5/5 on this pillar to clusters
// exporting to VBR over unverified TLS.
func profilesSkippingTLS(res Result) []kdl.RansomwareProfileSkippingTLS {
	out := make([]kdl.RansomwareProfileSkippingTLS, 0)
	for _, o := range res.Items("profiles") {
		// Both spellings: skipSSLVerify is the legacy key, skipCertVerification the
		// newer one, and profiles in the field carry either. Any occurrence being
		// true is what counts -- one unverified endpoint on a profile is an
		// unverified profile, and a shallow false must not mask a deeper true.
		if deepAnyTrue(mapAt(o.Object, "spec"), "skipSSLVerify", "skipCertVerification") {
			out = append(out, kdl.RansomwareProfileSkippingTLS{Name: name(o)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ransomwarePillarInputs names the collections and sections the score depends
// on. A grade is one number with no room in it for "partly unknown", so if any
// of these was not collected the whole section is declared uncomputed rather
// than published with a pillar scored zero for lack of evidence.
func ransomwarePillarInputs(res Result, r *kdl.Report) bool {
	if !res.Get("profiles").OK() || !res.Get("policies").OK() {
		return false
	}
	for _, section := range []string{"disasterRecovery", "k10Configuration"} {
		if r.NotCollected(section) {
			return false
		}
	}
	return true
}

// bestPracticesAnyAssessed reports whether at least one check got a real verdict.
//
// The threshold is "any", not "all", and the difference matters. kdl diff already
// skips an individual NOT_ASSESSED check -- it has to, or a customer who ran with
// full RBAC in Q1 and restricted RBAC in Q2 would get regressions that are purely
// a permissions change -- so a partly-assessed section carries no false-regression
// risk. Declaring the whole section because three of sixteen checks could not be
// evaluated would blank thirteen real verdicts out of the page to no purpose.
//
// The section is therefore declared only when nothing in it was assessed at all,
// which is the case where its contents say nothing about the cluster.
func bestPracticesAnyAssessed(r *kdl.Report) bool {
	bp := r.BestPractices
	for _, v := range []string{
		bp.DisasterRecovery, bp.Immutability, bp.PolicyPresets, bp.Monitoring,
		bp.ResourceLimits, bp.NamespaceProtection, bp.VMProtection,
		bp.Authentication, bp.Encryption, bp.AuditLogging,
		bp.SnapshotRetentionHigh, bp.SnapshotRetentionZero,
		bp.ExportRetentionExplicit, bp.ClusterScopedResources,
		bp.PoliciesWithoutExport,
	} {
		// N/A does not count. It is a real answer on its own -- the check does not
		// apply to this cluster -- but a section whose only non-unknown entries are
		// inapplicable checks still says nothing about the cluster's posture.
		if v != kdl.StatusNotAssessed && v != statusNA && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
