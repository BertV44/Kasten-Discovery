package diff

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BertV44/Kasten-Discovery/internal/schema"
)

// Kind classifies a finding by its effect on the customer's posture. Only
// Regression, Improvement and Neutral are counted in the summary; Info and OK
// are narration.
type Kind string

const (
	KindRegression  Kind = "regression"
	KindImprovement Kind = "improvement"
	KindNeutral     Kind = "neutral"
	KindInfo        Kind = "info"
	KindOK          Kind = "ok"
)

// Finding is one observation about one metric.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Label    string   `json:"label"`
	Baseline string   `json:"baseline,omitempty"`
	Current  string   `json:"current,omitempty"`
	Message  string   `json:"message"`
	Items    []string `json:"items,omitempty"`
}

// Section groups the findings of one report area.
type Section struct {
	Name     string    `json:"name"`
	Findings []Finding `json:"findings"`
	// Skipped marks a section that was not compared because one of the reports
	// declared it uncomputed. It is NOT the same as "nothing changed", and the
	// renderer must never let --summary collapse the two.
	Skipped bool `json:"skipped,omitempty"`
}

// Changed reports whether the section is worth showing even in summary mode.
//
// A skipped section counts. Suppressing it renders five unknown sections as a
// clean bill of health -- a silent false all-clear, in the mode a TAM actually
// runs for a quarterly review. That is the same failure as the fabricated
// alarm this gate was added to remove, pointing the other way.
func (s Section) Changed() bool {
	if s.Skipped {
		return true
	}
	for _, f := range s.Findings {
		switch f.Kind {
		case KindRegression, KindImprovement, KindNeutral:
			return true
		}
	}
	return false
}

// Summary is the machine-readable verdict. These four fields keep the field
// names kdl-diff.sh emits, because CI gates read them.
type Summary struct {
	Regressions    int `json:"regressions"`
	Improvements   int `json:"improvements"`
	NeutralChanges int `json:"neutralChanges"`
	ExitCode       int `json:"exitCode"`
}

// Result is the whole comparison.
type Result struct {
	Baseline Snapshot  `json:"baseline"`
	Current  Snapshot  `json:"current"`
	Sections []Section `json:"sections"`
	Summary  Summary   `json:"summary"`
}

// Snapshot identifies one side of the comparison.
type Snapshot struct {
	Path          string `json:"path"`
	KDLVersion    string `json:"kdlVersion"`
	KastenVersion string `json:"kastenVersion"`
	Platform      string `json:"platform"`
	RBACLimited   bool   `json:"rbacLimited"`
}

// builder accumulates findings for the section being compared.
type builder struct{ findings []Finding }

func (b *builder) add(f Finding) { b.findings = append(b.findings, f) }

func (b *builder) note(kind Kind, label, msg string) {
	b.add(Finding{Kind: kind, Label: label, Message: msg})
}

// direction says which way a metric is allowed to move without it being a
// regression.
type direction int

const (
	lowerIsBetter  direction = iota // failed actions, unprotected namespaces
	higherIsBetter                  // policies with export, immutable profiles
)

// intDelta compares a counter and classifies the move. Both sides must be
// meaningful: callers guard on assessability before calling, because a metric
// that was never assessed is not a zero (see comparableCounts).
func (b *builder) intDelta(label string, base, cur int, dir direction, unit string) {
	if base == cur {
		return
	}
	delta := cur - base
	kind := KindRegression
	verb := "worsened"
	switch dir {
	case lowerIsBetter:
		if delta < 0 {
			kind, verb = KindImprovement, "improved"
		}
	case higherIsBetter:
		if delta > 0 {
			kind, verb = KindImprovement, "improved"
		}
	}
	sign := "+"
	if delta < 0 {
		sign = "-"
		delta = -delta
	}
	if unit != "" {
		unit = " " + unit
	}
	b.add(Finding{
		Kind:     kind,
		Label:    label,
		Baseline: strconv.Itoa(base),
		Current:  strconv.Itoa(cur),
		Message:  fmt.Sprintf("%s: %d → %d (%s%d%s, %s)", label, base, cur, sign, delta, unit, verb),
	})
}

// setChange reports members that appeared and disappeared between the two
// snapshots. appearedKind lets the caller say whether a new member is bad (a
// new unprotected namespace) or merely worth knowing (a new policy).
func (b *builder) setChange(label string, base, cur []string, appearedKind, vanishedKind Kind, appearedMsg, vanishedMsg string) {
	if added := setDiff(cur, base); len(added) > 0 {
		b.add(Finding{
			Kind:    appearedKind,
			Label:   label,
			Current: strconv.Itoa(len(added)),
			Items:   added,
			Message: fmt.Sprintf("%d %s: %s", len(added), appearedMsg, strings.Join(added, ", ")),
		})
	}
	if removed := setDiff(base, cur); len(removed) > 0 {
		b.add(Finding{
			Kind:     vanishedKind,
			Label:    label,
			Baseline: strconv.Itoa(len(removed)),
			Items:    removed,
			Message:  fmt.Sprintf("%d %s: %s", len(removed), vanishedMsg, strings.Join(removed, ", ")),
		})
	}
}

// setDiff returns the members of a that are absent from b, deduplicated and
// sorted so two runs over the same data compare byte-for-byte.
func setDiff(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, v := range b {
		in[v] = true
	}
	seen := make(map[string]bool, len(a))
	var out []string
	for _, v := range a {
		if !in[v] && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Compare runs every section comparator over the two reports.
func Compare(base, cur *schema.Report, basePath, curPath string) Result {
	res := Result{
		Baseline: snapshotOf(base, basePath),
		Current:  snapshotOf(cur, curPath),
	}

	for _, s := range sections {
		var b builder
		skipped := notCollected(base, cur, s.source)
		if skipped {
			b.note(KindInfo, s.source,
				"Not computed by one of the two reports; not compared. An uncollected section is unknown, not empty.")
		} else {
			s.compare(base, cur, &b)
		}
		res.Sections = append(res.Sections, Section{Name: s.name, Findings: b.findings, Skipped: skipped})
	}

	for _, sec := range res.Sections {
		for _, f := range sec.Findings {
			switch f.Kind {
			case KindRegression:
				res.Summary.Regressions++
			case KindImprovement:
				res.Summary.Improvements++
			case KindNeutral:
				res.Summary.NeutralChanges++
			}
		}
	}
	res.Summary.ExitCode = cappedExit(res.Summary.Regressions)
	return res
}

// cappedExit turns a regression count into a process status. It is capped so
// the status stays a valid POSIX one and so 100 remains free for the usage
// error, matching kdl-diff.sh.
func cappedExit(regressions int) int {
	if regressions > 99 {
		return 99
	}
	return regressions
}

func snapshotOf(r *schema.Report, path string) Snapshot {
	return Snapshot{
		Path:          path,
		KDLVersion:    r.KDLVersion,
		KastenVersion: r.KastenVersion,
		Platform:      r.Platform,
		RBACLimited:   r.RBACLimited != nil && r.RBACLimited.Any,
	}
}

type sectionCmp struct {
	name    string
	compare func(base, cur *schema.Report, b *builder)
	// source names the report section this comparator reads. When either report
	// declares it uncomputed, the comparison is skipped: diffing a section
	// nobody collected against a real one manufactures findings of the most
	// alarming kind -- a missing licence block reads as "3 licences removed",
	// a missing DR block as "disaster recovery disabled". Empty means the
	// comparator reads several sections and guards itself.
	source string
}

// notCollected reports whether either side declared this section uncomputed.
// Both sides matter: the fabricated finding appears whichever direction the
// missing section is on.
func notCollected(base, cur *schema.Report, section string) bool {
	return section != "" && (base.NotCollected(section) || cur.NotCollected(section))
}

// sections is the comparison contract, in the order kdl-diff.sh prints it.
var sections = []sectionCmp{
	{name: "Metadata", compare: cmpMetadata},
	{name: "Ransomware Readiness", compare: cmpRansomware, source: "ransomwareReadiness"},
	{name: "Licence", compare: cmpLicence, source: "license"},
	{name: "Backup Health", compare: cmpHealth, source: "health"},
	{name: "Catalog", compare: cmpCatalog, source: "catalog"},
	{name: "Policies", compare: cmpPolicies, source: "policies"},
	{name: "Namespace Coverage", compare: cmpCoverage, source: "coverage"},
	{name: "Policy Analysis", compare: cmpPolicyAnalysis, source: "policyAnalysis"},
	{name: "Effective RPO", compare: cmpRPO, source: "policyRunStats.effectiveRpo"},
	{name: "K10 RBAC", compare: cmpRBAC, source: "k10Rbac"},
	{name: "Profiles", compare: cmpProfiles, source: "profiles"},
	{name: "Disaster Recovery", compare: cmpDR, source: "disasterRecovery"},
	{name: "Virtualization", compare: cmpVirtualization, source: "virtualization"},
	{name: "K10 Resource Limits", compare: cmpResourceLimits, source: "k10Resources"},
	{name: "Best Practices", compare: cmpBestPractices, source: "bestPractices"},
}

func cmpMetadata(base, cur *schema.Report, b *builder) {
	if base.KDLVersion != cur.KDLVersion {
		b.add(Finding{
			Kind: KindInfo, Label: "kdlVersion",
			Baseline: base.KDLVersion, Current: cur.KDLVersion,
			Message: fmt.Sprintf("KDL version: %s → %s", orNA(base.KDLVersion), orNA(cur.KDLVersion)),
		})
	}
	if base.KastenVersion != cur.KastenVersion {
		b.add(Finding{
			Kind: KindInfo, Label: "kastenVersion",
			Baseline: base.KastenVersion, Current: cur.KastenVersion,
			Message: fmt.Sprintf("Kasten version: %s → %s", orNA(base.KastenVersion), orNA(cur.KastenVersion)),
		})
	}

	// An RBAC-limited snapshot has empty sections, not zeroed ones. Comparing a
	// full snapshot against a limited one manufactures regressions out of reads
	// that were simply denied, so say it before any number is shown.
	baseLimited := base.RBACLimited != nil && base.RBACLimited.Any
	curLimited := cur.RBACLimited != nil && cur.RBACLimited.Any
	switch {
	case baseLimited && curLimited:
		b.note(KindInfo, "rbacLimited",
			"Both snapshots were collected with restricted RBAC: affected sections are empty, not zero.")
	case curLimited:
		b.note(KindInfo, "rbacLimited",
			"The current snapshot was collected with restricted RBAC but the baseline was not: a drop below may be a denied read rather than a real loss.")
	case baseLimited:
		b.note(KindInfo, "rbacLimited",
			"The baseline was collected with restricted RBAC but the current snapshot was not: a rise below may be newly visible data rather than real growth.")
	}
}

func cmpRansomware(base, cur *schema.Report, b *builder) {
	bg, cg := base.RansomwareReadiness.Grade, cur.RansomwareReadiness.Grade
	bs, cs := base.RansomwareReadiness.Score, cur.RansomwareReadiness.Score

	// An absent grade is not grade "" with score 0: the section did not exist
	// before KDL 2.0. Scoring that as a 45-point collapse would be a lie.
	switch {
	case bg == "" && cg == "":
		b.note(KindInfo, "grade", "Not available in either snapshot (KDL older than 2.0).")
		return
	case bg == "":
		b.add(Finding{
			Kind: KindNeutral, Label: "grade", Current: cg,
			Message: fmt.Sprintf("Score now available: %s (%d/%d)", cg, cs, cur.RansomwareReadiness.MaxScore),
		})
		return
	case cg == "":
		b.note(KindNeutral, "grade", "Score is no longer present in the current snapshot.")
		return
	}

	switch {
	case bg == cg && bs == cs:
		b.note(KindOK, "grade", fmt.Sprintf("No change — grade %s (%d/%d)", cg, cs, cur.RansomwareReadiness.MaxScore))
	case cs > bs:
		b.add(Finding{
			Kind: KindImprovement, Label: "grade", Baseline: bg, Current: cg,
			Message: fmt.Sprintf("Grade %s → %s (%d → %d, +%d pts)", bg, cg, bs, cs, cs-bs),
		})
	default:
		b.add(Finding{
			Kind: KindRegression, Label: "grade", Baseline: bg, Current: cg,
			Message: fmt.Sprintf("Grade %s → %s (%d → %d, -%d pts)", bg, cg, bs, cs, bs-cs),
		})
	}

	if bp, cp := base.RansomwareReadiness.BiggestGap.Pillar, cur.RansomwareReadiness.BiggestGap.Pillar; bp != cp && cp != "" {
		b.add(Finding{
			Kind: KindInfo, Label: "biggestGap", Baseline: bp, Current: cp,
			Message: fmt.Sprintf("Biggest gap moved: %s → %s", orNA(bp), cp),
		})
	}
}

func cmpLicence(base, cur *schema.Report, b *builder) {
	baseIDs := licenceIDs(base)
	curIDs := licenceIDs(cur)
	b.setChange("licences", baseIDs, curIDs,
		KindNeutral, KindRegression,
		"licence(s) added", "licence(s) removed")

	// Status transitions per licence, keyed by the same identity as the set diff.
	baseStatus := licenceStatus(base)
	for id, cs := range licenceStatus(cur) {
		bs, ok := baseStatus[id]
		if !ok || bs == cs {
			continue
		}
		kind := KindNeutral
		switch {
		case strings.EqualFold(cs, "EXPIRED"):
			kind = KindRegression
		case strings.EqualFold(bs, "EXPIRED") && strings.EqualFold(cs, "VALID"):
			// A renewed licence is an improvement, not a neutral change.
			kind = KindImprovement
		}
		b.add(Finding{
			Kind: kind, Label: "licenceStatus", Baseline: bs, Current: cs,
			Message: fmt.Sprintf("Licence %s: %s → %s", id, bs, cs),
		})
	}

	bc, cc := base.License.NodeConsumption, cur.License.NodeConsumption
	// assessed:false means listing nodes was denied. Current and Limit are then
	// meaningless and must not be diffed -- that is the misleading zero KDL.sh
	// goes out of its way to avoid.
	if !nodeConsumptionAssessed(bc) || !nodeConsumptionAssessed(cc) {
		b.note(KindInfo, "nodeConsumption",
			"Node consumption not assessed in at least one snapshot (RBAC denied the node listing); not compared.")
	} else {
		if bc.Status != cc.Status {
			kind := KindNeutral
			switch {
			case strings.EqualFold(cc.Status, "EXCEEDED"):
				kind = KindRegression
			case strings.EqualFold(bc.Status, "EXCEEDED"):
				// Coming back under the node limit is an improvement.
				kind = KindImprovement
			}
			b.add(Finding{
				Kind: kind, Label: "consumptionStatus", Baseline: bc.Status, Current: cc.Status,
				Message: fmt.Sprintf("Licence consumption: %s → %s (%d nodes)", orNA(bc.Status), orNA(cc.Status), cc.Current),
			})
		}
		// Node count is NOT diffed as a regression: adding a worker is ordinary
		// cluster growth, and kdl-diff.sh does not gate on it. Only the
		// entitlement status above can fail a gate.
		if bc.Current != cc.Current {
			b.add(Finding{
				Kind: KindInfo, Label: "nodesConsumed",
				Baseline: strconv.Itoa(bc.Current), Current: strconv.Itoa(cc.Current),
				Message: fmt.Sprintf("Nodes consumed: %d → %d", bc.Current, cc.Current),
			})
		}
	}
}

func licenceIDs(r *schema.Report) []string {
	out := make([]string, 0, len(r.License.Licenses))
	for _, l := range r.License.Licenses {
		out = append(out, licenceIdentity(l))
	}
	return out
}

func licenceStatus(r *schema.Report) map[string]string {
	out := make(map[string]string, len(r.License.Licenses))
	for _, l := range r.License.Licenses {
		out[licenceIdentity(l)] = l.Status
	}
	return out
}

func cmpHealth(base, cur *schema.Report, b *builder) {
	bb, cb := base.Health.Backups, cur.Health.Backups

	// successRate is a string ("94.3") because KDL emits "N/A" when there is
	// nothing finished to rate. Only compare two real numbers.
	bsr, bok := parseRate(bb.SuccessRate)
	csr, cok := parseRate(cb.SuccessRate)
	switch {
	case !bok || !cok:
		b.note(KindInfo, "successRate",
			fmt.Sprintf("Success rate not comparable (%s → %s).", orNA(bb.SuccessRate), orNA(cb.SuccessRate)))
	case csr < bsr:
		b.add(Finding{
			Kind: KindRegression, Label: "successRate", Baseline: bb.SuccessRate, Current: cb.SuccessRate,
			Message: fmt.Sprintf("Success rate: %s%% → %s%%", bb.SuccessRate, cb.SuccessRate),
		})
	case csr > bsr:
		b.add(Finding{
			Kind: KindImprovement, Label: "successRate", Baseline: bb.SuccessRate, Current: cb.SuccessRate,
			Message: fmt.Sprintf("Success rate: %s%% → %s%%", bb.SuccessRate, cb.SuccessRate),
		})
	}

	b.intDelta("Failed actions", bb.FailedActions, cb.FailedActions, lowerIsBetter, "")

	// Pod readiness is reported but not gated on: kdl-diff.sh does not, and a
	// pod restarting during collection would fail a CI gate on a healthy cluster.
	if base.Health.Pods.Ready != cur.Health.Pods.Ready {
		b.add(Finding{
			Kind: KindInfo, Label: "podsReady",
			Baseline: strconv.Itoa(base.Health.Pods.Ready), Current: strconv.Itoa(cur.Health.Pods.Ready),
			Message: fmt.Sprintf("K10 pods ready: %d → %d", base.Health.Pods.Ready, cur.Health.Pods.Ready),
		})
	}
}

// cmpCatalog classifies a free-space move the way kdl-diff.sh does: only a drop
// that lands below 20% is a regression, and below 10% it is critical. A fall
// from 95% to 85% is capacity being used, not a fault -- grading it a
// regression fails a CI gate on a healthy cluster.
func cmpCatalog(base, cur *schema.Report, b *builder) {
	// The section is absent from a report that never collected it, and 0% free
	// reads as a catalog about to fail. Only compare two figures that exist.
	if !catalogPresent(base) || !catalogPresent(cur) {
		b.note(KindInfo, "catalogFreeSpace",
			"Catalog usage not present in both snapshots; not compared.")
		return
	}

	bf, cf := base.Catalog.FreeSpacePercent, cur.Catalog.FreeSpacePercent
	if bf == cf {
		return
	}
	if cf > bf {
		b.add(Finding{
			Kind: KindImprovement, Label: "catalogFreeSpace",
			Baseline: strconv.Itoa(bf), Current: strconv.Itoa(cf),
			Message: fmt.Sprintf("Catalog free space: %d%% → %d%% (+%d pts)", bf, cf, cf-bf),
		})
		return
	}

	msg := fmt.Sprintf("Catalog free space: %d%% → %d%% (-%d pts)", bf, cf, bf-cf)
	kind := KindNeutral
	switch {
	case cf < 10:
		kind, msg = KindRegression, msg+" — CRITICAL"
	case cf < 20:
		kind = KindRegression
	}
	b.add(Finding{
		Kind: kind, Label: "catalogFreeSpace",
		Baseline: strconv.Itoa(bf), Current: strconv.Itoa(cf), Message: msg,
	})
}

// catalogPresent distinguishes a catalog that was measured from one that was
// never collected. A PVC name is the cheapest positive evidence the section ran.
func catalogPresent(r *schema.Report) bool {
	return r.Catalog.PVCName != "" || r.Catalog.Size != "" ||
		r.Catalog.FreeSpacePercent != 0 || r.Catalog.UsedPercent != 0
}

func cmpPolicies(base, cur *schema.Report, b *builder) {
	b.setChange("policies", policyNames(base), policyNames(cur),
		KindNeutral, KindNeutral,
		"policy/policies added", "policy/policies removed")
	b.intDelta("Policies with export", base.Policies.WithExport, cur.Policies.WithExport, higherIsBetter, "")
}

func cmpCoverage(base, cur *schema.Report, b *builder) {
	b.setChange("unprotectedNamespaces",
		base.Coverage.UnprotectedNamespaces.Items, cur.Coverage.UnprotectedNamespaces.Items,
		KindRegression, KindImprovement,
		"new unprotected namespace(s)", "namespace(s) now protected")

	if base.Coverage.HasCatchallPolicy != cur.Coverage.HasCatchallPolicy {
		kind := KindImprovement
		if !cur.Coverage.HasCatchallPolicy {
			kind = KindNeutral
		}
		b.add(Finding{
			Kind: kind, Label: "hasCatchallPolicy",
			Baseline: strconv.FormatBool(base.Coverage.HasCatchallPolicy),
			Current:  strconv.FormatBool(cur.Coverage.HasCatchallPolicy),
			Message: fmt.Sprintf("Catch-all policy present: %t → %t",
				base.Coverage.HasCatchallPolicy, cur.Coverage.HasCatchallPolicy),
		})
	}
}

func cmpPolicyAnalysis(base, cur *schema.Report, b *builder) {
	b.setChange("emptyPolicies", emptyPolicyNames(base), emptyPolicyNames(cur),
		KindRegression, KindImprovement,
		"new empty policy/policies (coverage = 0)", "policy/policies no longer empty")

	// Only compare the redundancy figure when both snapshots actually computed
	// the analysis: absent is not zero, and treating it as zero turns a section
	// nobody ran into a fresh regression.
	redundancyDeclared := notCollected(base, cur, "policyAnalysis.summary.redundantPairsGenuine")
	if !redundancyDeclared && policyAnalysisPresent(base) && policyAnalysisPresent(cur) {
		b.intDelta("Genuine redundant pairs",
			base.PolicyAnalysis.Summary.RedundantPairsGenuine,
			cur.PolicyAnalysis.Summary.RedundantPairsGenuine, lowerIsBetter, "")
	} else {
		b.note(KindInfo, "redundantPairs",
			"Redundancy analysis not computed by both reports; not compared.")
	}

	// Dead namespace references are reported, not gated: kdl-diff.sh does not
	// fail a run on them, and the named policies below carry the detail.
	b.setChange("nonExistingReferences", nonExistingRefs(base), nonExistingRefs(cur),
		KindInfo, KindInfo,
		"policy/policies now reference a non-existing namespace",
		"policy/policies no longer reference a non-existing namespace")
}

func cmpRPO(base, cur *schema.Report, b *builder) {
	b.setChange("rpoDrift", driftingPolicies(base), driftingPolicies(cur),
		KindRegression, KindImprovement,
		"policy/policies now in RPO drift", "policy/policies no longer drifting")
}

func cmpRBAC(base, cur *schema.Report, b *builder) {
	// A denied RBAC read yields an empty inventory. Reporting every subject as
	// "lost access" would turn a permission problem into a fake security event.
	if !base.K10RBAC.Accessibility.FullyAccessible || !cur.K10RBAC.Accessibility.FullyAccessible {
		b.note(KindInfo, "rbacAccessibility",
			"RBAC inventory incomplete in at least one snapshot; subject changes not compared.")
		return
	}

	baseSubj, curSubj := rbacSubjects(base), rbacSubjects(cur)

	// Humans are the audit-relevant subjects; ServiceAccounts churn with every
	// K10 upgrade and would drown the signal.
	b.setChange("humanSubjects", humansOnly(baseSubj), humansOnly(curSubj),
		KindNeutral, KindNeutral,
		"human subject(s) gained K10 access", "human subject(s) lost K10 access")

	added := len(setDiff(curSubj, baseSubj)) - len(setDiff(humansOnly(curSubj), humansOnly(baseSubj)))
	removed := len(setDiff(baseSubj, curSubj)) - len(setDiff(humansOnly(baseSubj), humansOnly(curSubj)))
	if added > 0 || removed > 0 {
		b.note(KindInfo, "serviceAccounts",
			fmt.Sprintf("ServiceAccount changes: +%d / -%d", added, removed))
	}
}

func cmpProfiles(base, cur *schema.Report, b *builder) {
	b.setChange("profiles", profileNames(base), profileNames(cur),
		KindNeutral, KindNeutral,
		"profile(s) added", "profile(s) removed")
	b.intDelta("Immutable profiles", base.Profiles.ImmutableCount, cur.Profiles.ImmutableCount, higherIsBetter, "")
}

func cmpDR(base, cur *schema.Report, b *builder) {
	if base.DisasterRecovery.Enabled == cur.DisasterRecovery.Enabled {
		return
	}
	if cur.DisasterRecovery.Enabled {
		b.add(Finding{
			Kind: KindImprovement, Label: "disasterRecovery", Baseline: "false", Current: "true",
			Message: "K10 disaster recovery enabled",
		})
		return
	}
	b.add(Finding{
		Kind: KindRegression, Label: "disasterRecovery", Baseline: "true", Current: "false",
		Message: "K10 disaster recovery disabled",
	})
}

func cmpVirtualization(base, cur *schema.Report, b *builder) {
	// The COUNT is what gates, and the list only names the VMs.
	//
	// Getting this split wrong has now failed in both directions. Calling both
	// intDelta and setChange regressions counted one event twice, and the exit
	// code is read as a count. Dropping intDelta then left the count ungated --
	// and unprotectedVmList is `omitempty` and absent from every real report
	// available, so a cluster whose unprotected VMs went 1 to 4 reported "No
	// change". Namespace coverage can rely on its list because
	// unprotectedNamespaces.items is not optional; this one cannot.
	b.intDelta("Unprotected VMs",
		base.Virtualization.Protection.UnprotectedVMs,
		cur.Virtualization.Protection.UnprotectedVMs, lowerIsBetter, "")

	b.setChange("unprotectedVMs",
		base.Virtualization.Protection.UnprotectedVMList,
		cur.Virtualization.Protection.UnprotectedVMList,
		KindInfo, KindInfo,
		"newly unprotected VM(s)", "VM(s) now protected")
}

func cmpResourceLimits(base, cur *schema.Report, b *builder) {
	b.intDelta("Containers without limits",
		base.K10Resources.Summary.WithoutLimits,
		cur.K10Resources.Summary.WithoutLimits, lowerIsBetter, "")
}

// bestPracticeStates are the values KDL emits that mean the check passes. The
// list is Kasten's vocabulary, not ours: inventing a value here would silently
// reclassify a real state as unknown.
var bestPracticeGood = map[string]bool{
	"ENABLED": true, "CONFIGURED": true, "COMPLETE": true, "OK": true, "IN_USE": true,
}

func cmpBestPractices(base, cur *schema.Report, b *builder) {
	for _, bp := range bestPracticeChecks {
		bv, cv := bp.get(&base.BestPractices), bp.get(&cur.BestPractices)
		// An absent value is not a failing one: vmSnapshotConsistency arrived in
		// KDL 2.2.0 and is simply missing from older baselines.
		//
		// NOT_ASSESSED is treated the same way, and for the stronger reason.
		// KDL.sh writes it when RBAC denied the read the check needs, so a
		// customer who ran with full RBAC in Q1 and restricted RBAC in Q2 would
		// otherwise get a regression that is purely a permissions change -- the
		// very misreporting that value exists to prevent.
		if bv == "" || cv == "" || bv == cv ||
			bv == schema.StatusNotAssessed || cv == schema.StatusNotAssessed {
			continue
		}
		bGood, cGood := bestPracticeGood[bv], bestPracticeGood[cv]
		kind := KindNeutral
		switch {
		case cGood && !bGood:
			kind = KindImprovement
		case !cGood && bGood:
			kind = KindRegression
		}
		b.add(Finding{
			Kind: kind, Label: bp.key, Baseline: bv, Current: cv,
			Message: fmt.Sprintf("%s: %s → %s", bp.key, bv, cv),
		})
	}
}

// bestPracticeChecks mirrors the BP_LIST of kdl-diff.sh, in its order.
var bestPracticeChecks = []struct {
	key string
	get func(*schema.BestPractices) string
}{
	{"disasterRecovery", func(p *schema.BestPractices) string { return p.DisasterRecovery }},
	{"immutability", func(p *schema.BestPractices) string { return p.Immutability }},
	{"policyPresets", func(p *schema.BestPractices) string { return p.PolicyPresets }},
	{"monitoring", func(p *schema.BestPractices) string { return p.Monitoring }},
	{"resourceLimits", func(p *schema.BestPractices) string { return p.ResourceLimits }},
	{"namespaceProtection", func(p *schema.BestPractices) string { return p.NamespaceProtection }},
	{"vmProtection", func(p *schema.BestPractices) string { return p.VMProtection }},
	{"vmSnapshotConsistency", func(p *schema.BestPractices) string { return p.VMSnapshotConsistency }},
	{"authentication", func(p *schema.BestPractices) string { return p.Authentication }},
	{"encryption", func(p *schema.BestPractices) string { return p.Encryption }},
	{"auditLogging", func(p *schema.BestPractices) string { return p.AuditLogging }},
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func parseRate(s string) (float64, bool) {
	if s == "" || strings.EqualFold(s, "N/A") {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	return v, err == nil
}

// nodeConsumptionAssessed treats a report predating KDL 2.1.1 (nil Assessed) as
// assessed: those versions only emitted the block when they had read the nodes.
func nodeConsumptionAssessed(c schema.LicenseNodeConsumption) bool {
	return c.Assessed == nil || *c.Assessed
}
