package diff

import (
	"strings"

	"github.com/BertV44/Kasten-Discovery/internal/schema"
)

// The extractors below all reduce a report section to the identity set the diff
// compares. Identity is deliberately not "the whole object": two snapshots of
// the same cluster differ in timestamps, ages and durations by construction, so
// diffing full objects would report noise as change.

// licenceIdentity keys a licence by its licence ID, falling back to the secret
// name. The ID survives a secret being recreated, which the secret name does
// not -- and a licence that merely moved secrets is not a licence that was
// removed.
func licenceIdentity(l schema.LicenseEntry) string {
	if l.ID != "" {
		return l.ID
	}
	if l.Secret != "" {
		return l.Secret
	}
	return "(unidentified licence)"
}

func policyNames(r *schema.Report) []string {
	out := make([]string, 0, len(r.Policies.Items))
	for _, p := range r.Policies.Items {
		out = append(out, p.Name)
	}
	return out
}

func profileNames(r *schema.Report) []string {
	out := make([]string, 0, len(r.Profiles.Items))
	for _, p := range r.Profiles.Items {
		out = append(out, p.Name)
	}
	return out
}

// policyAnalysisPresent distinguishes an analysis that ran and found nothing
// from one that was never computed. Absent is not zero: diffing an absent
// analysis against a real one manufactures a regression out of a section
// nobody ran.
func policyAnalysisPresent(r *schema.Report) bool {
	s := r.PolicyAnalysis.Summary
	return s.TotalPolicies > 0 || s.RedundantPairCount > 0 || s.RedundantPairsGenuine > 0 ||
		len(r.PolicyAnalysis.Resolved) > 0 || len(r.PolicyAnalysis.EmptyPolicies) > 0
}

// nonExistingRefs names the policies pointing at namespaces that do not exist,
// so the diff can name them rather than only counting them.
func nonExistingRefs(r *schema.Report) []string {
	out := make([]string, 0, len(r.PolicyAnalysis.PoliciesWithNonExistingReferences))
	for _, p := range r.PolicyAnalysis.PoliciesWithNonExistingReferences {
		out = append(out, p.Name)
	}
	return out
}

func emptyPolicyNames(r *schema.Report) []string {
	out := make([]string, 0, len(r.PolicyAnalysis.EmptyPolicies))
	for _, p := range r.PolicyAnalysis.EmptyPolicies {
		out = append(out, p.Name)
	}
	return out
}

// driftingPolicies lists only the policies KDL actually judged to be drifting.
// Drift is a *bool: nil means KDL could not judge (custom cron, no declared
// frequency, or too few samples). Treating nil as "not drifting" is right for
// this set, but treating it as "drifting" would invent regressions out of
// unjudgeable policies.
func driftingPolicies(r *schema.Report) []string {
	var out []string
	for _, it := range r.PolicyRunStats.EffectiveRPO.Items {
		if it.Drift != nil && *it.Drift {
			out = append(out, it.Name)
		}
	}
	return out
}

// rbacSubjects keys a subject by "kind/name" and deliberately drops the
// namespace: a ServiceAccount does not move between namespaces across
// snapshots, and including it would make an unchanged subject look replaced.
func rbacSubjects(r *schema.Report) []string {
	out := make([]string, 0, len(r.K10RBAC.Subjects.Items))
	for _, s := range r.K10RBAC.Subjects.Items {
		out = append(out, s.Kind+"/"+s.Name)
	}
	return out
}

// humansOnly keeps the audit-relevant subjects. ServiceAccounts are K10's own
// plumbing and churn on every upgrade.
func humansOnly(subjects []string) []string {
	var out []string
	for _, s := range subjects {
		if strings.HasPrefix(s, "User/") || strings.HasPrefix(s, "Group/") {
			out = append(out, s)
		}
	}
	return out
}
