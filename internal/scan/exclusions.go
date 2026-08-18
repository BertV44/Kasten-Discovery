package scan

// Deliberate opt-outs, and what is left once they are subtracted.
//
// "Unprotected" means "not selected by any application policy", and on a cluster
// that deliberately opts namespaces out -- globally through excludedApps, or per
// policy through a NotIn selector -- most of that count is by design. Reporting
// the raw figure buries the handful of namespaces somebody actually needs to act
// on underneath the ones they already decided about.

import (
	"sort"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
)

// buildPolicyExclusions lists the policies that carry an appNamespace NotIn
// selector, with both the patterns and the namespaces they really resolve to.
//
// The patterns alone do not say whether anything is excluded: "kube-*" on a
// cluster with no kube- namespace excludes nothing, and a reader shown only the
// pattern cannot tell those apart.
func buildPolicyExclusions(res Result, r *kdl.Report) {
	if !res.Get("policies").OK() {
		return
	}
	live := make([]string, 0, len(r.Coverage.NamespacesInventory.Items))
	for _, ns := range r.Coverage.NamespacesInventory.Items {
		live = append(live, ns.Name)
	}

	byPolicy := make([]kdl.K10ConfigurationPolicyExclusion, 0)
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) {
			continue
		}
		patterns := p.Selector.ExcludedNamespacePatterns()
		if len(patterns) == 0 {
			continue
		}
		matched := make([]string, 0)
		for _, ns := range live {
			if kdl.GlobAny(patterns, ns) {
				matched = append(matched, ns)
			}
		}
		sort.Strings(matched)
		byPolicy = append(byPolicy, kdl.K10ConfigurationPolicyExclusion{
			Policy:            p.Name,
			Patterns:          patterns,
			MatchedNamespaces: matched,
		})
	}
	sort.Slice(byPolicy, func(i, j int) bool { return byPolicy[i].Policy < byPolicy[j].Policy })

	r.K10Configuration.PolicyExclusions = &kdl.K10ConfigurationPolicyExclusions{
		Count: len(byPolicy), ByPolicy: byPolicy,
	}
}

// buildUnprotectedBreakdown splits the unprotected count into what was decided
// and what is left over.
//
// It fails toward "actionable" rather than "excluded" wherever the inputs are
// incomplete. A miscount that shows a deliberate exclusion as a gap costs
// somebody five minutes; one that hides a real gap behind an exclusion nobody
// configured costs them the data.
func buildUnprotectedBreakdown(r *kdl.Report, cfg installConfig) {
	unprotected := r.Coverage.UnprotectedNamespaces.Items

	excludedByHelm := map[string]bool{}
	for _, app := range r.K10Configuration.ExcludedApps.Items {
		excludedByHelm[app] = true
	}
	excludedByPolicy := map[string]bool{}
	if pe := r.K10Configuration.PolicyExclusions; pe != nil {
		for _, e := range pe.ByPolicy {
			for _, ns := range e.MatchedNamespaces {
				excludedByPolicy[ns] = true
			}
		}
	}

	breakdown := kdl.CoverageUnprotectedBreakdown{
		Total:                len(unprotected),
		ActionableNamespaces: make([]string, 0, len(unprotected)),
	}
	for _, ns := range unprotected {
		byHelm, byPolicy := excludedByHelm[ns], excludedByPolicy[ns]
		if byHelm {
			breakdown.ExcludedByHelm++
		}
		if byPolicy {
			breakdown.ExcludedByPolicy++
		}
		// A namespace excluded both ways is one decision, not two: the union is
		// what gets subtracted, so the two counts above can overlap while
		// deliberatelyExcluded and actionable still add up to the total.
		if byHelm || byPolicy {
			breakdown.DeliberatelyExcluded++
			continue
		}
		breakdown.Actionable++
		breakdown.ActionableNamespaces = append(breakdown.ActionableNamespaces, ns)
	}
	r.Coverage.UnprotectedBreakdown = &breakdown
}
