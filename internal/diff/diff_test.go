package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BertV44/Kasten-Discovery/internal/schema"
)

// decode builds a report from a JSON fragment. Lenient, like the diff itself.
func decode(t *testing.T, doc string) *schema.Report {
	t.Helper()
	var r schema.Report
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return &r
}

// findings flattens the result so a test can assert on one metric without
// caring which section it landed in.
func findings(res Result) map[string]Finding {
	out := map[string]Finding{}
	for _, s := range res.Sections {
		for _, f := range s.Findings {
			out[f.Label] = f
		}
	}
	return out
}

func compare(t *testing.T, baseDoc, curDoc string) Result {
	t.Helper()
	return Compare(decode(t, baseDoc), decode(t, curDoc), "base.json", "cur.json")
}

// TestAbsentSectionIsNotARegression: the ransomware score arrived in KDL 2.0.
// Diffing a 1.9 baseline against a 2.0 snapshot must not read the missing
// baseline as grade "" scoring 0, which would report a brand-new section as a
// catastrophic collapse.
func TestAbsentSectionIsNotARegression(t *testing.T) {
	res := compare(t,
		`{"kdlVersion": "1.9"}`,
		`{"kdlVersion": "2.0", "ransomwareReadiness": {"grade": "B", "score": 75, "maxScore": 100}}`)

	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: a section that did not exist in the baseline is not a regression", res.Summary.Regressions)
	}
	f, ok := findings(res)["grade"]
	if !ok {
		t.Fatal("no finding for the newly available grade")
	}
	if f.Kind != KindNeutral {
		t.Errorf("kind = %q, want %q", f.Kind, KindNeutral)
	}
}

// TestBothSectionsAbsentSaysSoRatherThanClaimingParity: an empty section in
// both snapshots is "not available", not "no change" -- the corollary of the
// no-misleading-zero rule. Reporting parity would tell a TAM the posture was
// verified when nothing was ever read.
func TestBothSectionsAbsentSaysSoRatherThanClaimingParity(t *testing.T) {
	res := compare(t, `{"kdlVersion": "1.9"}`, `{"kdlVersion": "1.9"}`)

	f, ok := findings(res)["grade"]
	if !ok {
		t.Fatal("no finding at all for an absent ransomware section")
	}
	if f.Kind != KindInfo {
		t.Errorf("kind = %q, want %q", f.Kind, KindInfo)
	}
	if !strings.Contains(strings.ToLower(f.Message), "not available") {
		t.Errorf("message = %q, want it to say the section is not available", f.Message)
	}
}

// TestDeniedNodeReadIsNotDiffed: assessed:false means RBAC refused the node
// listing, so Current is meaningless. Diffing it produces a regression out of a
// permission change -- the misleading zero KDL.sh goes out of its way to avoid.
func TestDeniedNodeReadIsNotDiffed(t *testing.T) {
	const base = `{"license": {"nodeConsumption": {"current": 12, "limit": 25, "status": "OK", "assessed": true}}}`
	const cur = `{"license": {"nodeConsumption": {"current": 0, "limit": 0, "status": "", "assessed": false}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: a denied read is not a drop to zero", res.Summary.Regressions)
	}
	f, ok := findings(res)["nodeConsumption"]
	if !ok {
		t.Fatal("a denied node read must be reported, not silently skipped")
	}
	if f.Kind != KindInfo {
		t.Errorf("kind = %q, want %q", f.Kind, KindInfo)
	}
}

// TestDeniedRBACReadDoesNotInventAccessLoss: an RBAC inventory that could not
// be listed is empty, not emptied. Comparing it against a full baseline would
// report every subject as having lost access -- a fake security event.
func TestDeniedRBACReadDoesNotInventAccessLoss(t *testing.T) {
	const base = `{"k10Rbac": {"accessibility": {"fullyAccessible": true},
	  "subjects": {"total": 2, "items": [{"kind": "Group", "name": "k10:admins"}, {"kind": "User", "name": "alice"}]}}}`
	const cur = `{"k10Rbac": {"accessibility": {"fullyAccessible": false},
	  "subjects": {"total": 0, "items": []}}}`

	res := compare(t, base, cur)
	for _, f := range findings(res) {
		if f.Kind == KindNeutral || f.Kind == KindRegression {
			t.Errorf("a denied RBAC read produced %q: %s", f.Kind, f.Message)
		}
	}
}

// TestRBACLimitedSnapshotIsFlaggedUpFront: when only one side ran with
// restricted RBAC, every number below it is suspect. The reader must be told
// before being shown the deltas.
func TestRBACLimitedSnapshotIsFlaggedUpFront(t *testing.T) {
	const base = `{"kdlVersion": "2.2.0"}`
	const cur = `{"kdlVersion": "2.2.0", "rbacLimited": {"any": true, "denied": ["nodes"]}}`

	f, ok := findings(compare(t, base, cur))["rbacLimited"]
	if !ok {
		t.Fatal("an RBAC-limited current snapshot is not flagged")
	}
	if f.Kind != KindInfo {
		t.Errorf("kind = %q, want %q", f.Kind, KindInfo)
	}
}

// TestBestPracticeVocabularyIsKastens: the pass list must hold the values the
// emitter really writes, and nothing else.
//
// The first version of this test listed the same five strings the pass table
// holds and asserted they were in it -- it could not fail unless someone
// deleted an entry, and adding a wrong value would have passed. It is now
// driven by the failing vocabulary a real KDL report actually contains, which
// is the half that has to stay OUT of the pass set: mistakenly admitting one of
// these would render a genuine regression as an improvement.
func TestBestPracticeVocabularyIsKastens(t *testing.T) {
	// Every non-passing status observed in real KDL output. PARTIAL and WARN are
	// the dangerous ones: they read as mild, and treating them as passing hides
	// a real gap.
	for _, failing := range []string{
		"NOT_CONFIGURED", "NOT_ENABLED", "GAPS_DETECTED",
		"CONFIGURED_INCOMPLETE", "PARTIAL", "WARN",
	} {
		if bestPracticeGood[failing] {
			t.Errorf("%q is a non-passing status in real KDL output but counts as passing", failing)
		}
	}
	// The pass set must not have grown silently either: an extra entry is how a
	// failing state gets quietly reclassified.
	if len(bestPracticeGood) != 5 {
		t.Errorf("the pass set holds %d values, want the 5 KDL emits (%v)",
			len(bestPracticeGood), bestPracticeGood)
	}

	// End-to-end control on the classification itself, not just the table.
	res := compare(t,
		`{"bestPractices": {"monitoring": "ENABLED", "immutability": "CONFIGURED"}}`,
		`{"bestPractices": {"monitoring": "NOT_ENABLED", "immutability": "PARTIAL"}}`)
	if res.Summary.Regressions != 2 {
		t.Errorf("regressions = %d, want 2: both checks moved from a passing to a non-passing state",
			res.Summary.Regressions)
	}
}

// TestBestPracticeAbsentValueIsNotAFailure: vmSnapshotConsistency arrived in
// KDL 2.2.0. An older baseline simply lacks it, which is not a check that was
// passing and then broke.
func TestBestPracticeAbsentValueIsNotAFailure(t *testing.T) {
	const base = `{"bestPractices": {"monitoring": "ENABLED"}}`
	const cur = `{"bestPractices": {"monitoring": "ENABLED", "vmSnapshotConsistency": "GAPS"}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: a check absent from the baseline cannot have regressed", res.Summary.Regressions)
	}
}

// TestUnjudgeableDriftIsNotDrift: RPO drift is a *bool and is null when KDL
// could not judge (custom cron, too few samples). Counting null as drifting
// would manufacture a regression out of a policy that merely stopped being
// judgeable.
//
// The baseline judges "b" as on target and the current snapshot can no longer
// judge it at all. Were null read as drift, "b" would appear only in the
// current set and be reported as newly drifting.
func TestUnjudgeableDriftIsNotDrift(t *testing.T) {
	const base = `{"policyRunStats": {"effectiveRpo": {"items": [
	  {"name": "a", "samples": 9, "drift": false}, {"name": "b", "samples": 9, "drift": false}]}}}`
	const cur = `{"policyRunStats": {"effectiveRpo": {"items": [
	  {"name": "a", "samples": 9, "drift": false}, {"name": "b", "samples": 1, "drift": null}]}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: a null drift verdict is not drift", res.Summary.Regressions)
	}
}

// TestNewDriftIsARegression is the positive control for the test above: a
// policy that really started drifting must still be caught.
func TestNewDriftIsARegression(t *testing.T) {
	const base = `{"policyRunStats": {"effectiveRpo": {"items": [{"name": "a", "drift": false}]}}}`
	const cur = `{"policyRunStats": {"effectiveRpo": {"items": [{"name": "a", "drift": true}]}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 1 {
		t.Fatalf("regressions = %d, want 1", res.Summary.Regressions)
	}
	if f := findings(res)["rpoDrift"]; !strings.Contains(f.Message, "a") {
		t.Errorf("message = %q, want the drifting policy named", f.Message)
	}
}

// TestLicenceIdentityIsTheLicenceID: keying a licence by its secret name makes
// a licence that merely moved secrets look removed and re-added, which reads as
// an entitlement loss.
func TestLicenceIdentityIsTheLicenceID(t *testing.T) {
	const base = `{"license": {"licenses": [{"secret": "k10-license", "id": "abc-123", "status": "VALID"}]}}`
	const cur = `{"license": {"licenses": [{"secret": "k10-license-xyz", "id": "abc-123", "status": "VALID"}]}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: the same licence in a new secret is not a removed licence", res.Summary.Regressions)
	}
}

// TestRemovedLicenceIsARegression is the positive control for the identity test.
func TestRemovedLicenceIsARegression(t *testing.T) {
	const base = `{"license": {"licenses": [{"secret": "s1", "id": "abc-123", "status": "VALID"}]}}`
	const cur = `{"license": {"licenses": []}}`

	if got := compare(t, base, cur).Summary.Regressions; got != 1 {
		t.Errorf("regressions = %d, want 1", got)
	}
}

// TestExitCodeIsCappedAt99 keeps the status a valid POSIX one and leaves 100
// free for the usage error. Tested on the capping function directly: reaching
// 100 real regressions through the comparators is not reachable in practice
// (a whole changed set is one finding), so a fixture-driven test here would
// pass without ever exercising the cap.
func TestExitCodeIsCappedAt99(t *testing.T) {
	for _, tc := range []struct{ regressions, want int }{
		{0, 0}, {1, 1}, {99, 99}, {100, 99}, {5000, 99},
	} {
		if got := cappedExit(tc.regressions); got != tc.want {
			t.Errorf("cappedExit(%d) = %d, want %d", tc.regressions, got, tc.want)
		}
	}
}

// TestUsageExitIsDistinctFromRegressionCount: a CI gate reads the status as a
// number of regressions, so the usage error must not be mistakable for one.
func TestUsageExitIsDistinctFromRegressionCount(t *testing.T) {
	if usageExit <= 99 {
		t.Errorf("usageExit = %d, want it above the capped regression range", usageExit)
	}
}

// TestIdenticalReportsAreClean: the same report against itself must produce no
// regression at all. Anything that fires here is comparing a field that moves
// on its own between two runs.
func TestIdenticalReportsAreClean(t *testing.T) {
	doc := `{
	  "kdlVersion": "2.2.0", "kastenVersion": "9.0.0",
	  "ransomwareReadiness": {"grade": "B", "score": 75, "maxScore": 100},
	  "license": {"licenses": [{"secret": "s", "id": "i", "status": "VALID"}],
	              "nodeConsumption": {"current": 4, "limit": 25, "status": "OK", "assessed": true}},
	  "health": {"pods": {"ready": 21}, "backups": {"failedActions": 2, "successRate": "94.3"}},
	  "catalog": {"freeSpacePercent": 95},
	  "policies": {"count": 2, "withExport": 1, "items": [{"name": "p1"}, {"name": "p2"}]},
	  "coverage": {"hasCatchallPolicy": true, "unprotectedNamespaces": {"items": ["x"]}},
	  "policyAnalysis": {"summary": {"redundantPairsGenuine": 3, "withNonExistingNsCount": 1},
	                     "emptyPolicies": [{"name": "e1"}]},
	  "policyRunStats": {"effectiveRpo": {"items": [{"name": "p1", "drift": true}]}},
	  "k10Rbac": {"accessibility": {"fullyAccessible": true},
	              "subjects": {"items": [{"kind": "Group", "name": "k10:admins"}]}},
	  "profiles": {"count": 1, "immutableCount": 1, "items": [{"name": "prof"}]},
	  "disasterRecovery": {"enabled": true},
	  "virtualization": {"protection": {"unprotectedVMs": 1, "unprotectedVmList": ["ns/vm"]}},
	  "k10Resources": {"summary": {"withoutLimits": 27}},
	  "bestPractices": {"monitoring": "ENABLED", "immutability": "NOT_CONFIGURED"}
	}`

	res := compare(t, doc, doc)
	if res.Summary.Regressions != 0 || res.Summary.Improvements != 0 || res.Summary.NeutralChanges != 0 {
		t.Errorf("a report against itself moved: %d regressions, %d improvements, %d neutral",
			res.Summary.Regressions, res.Summary.Improvements, res.Summary.NeutralChanges)
		for _, s := range res.Sections {
			for _, f := range s.Findings {
				if f.Kind != KindOK && f.Kind != KindInfo {
					t.Logf("  %s: [%s] %s", s.Name, f.Kind, f.Message)
				}
			}
		}
	}
	if res.Summary.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.Summary.ExitCode)
	}
}

// TestJSONSummaryKeepsShellFieldNames: CI gates built against kdl-diff.sh read
// these four keys. Renaming one silently breaks every gate.
func TestJSONSummaryKeepsShellFieldNames(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, compare(t, `{}`, `{}`)); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out struct {
		Summary map[string]json.RawMessage `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"regressions", "improvements", "neutralChanges", "exitCode"} {
		if _, ok := out.Summary[key]; !ok {
			t.Errorf("summary.%s is missing; CI gates written against kdl-diff.sh read it", key)
		}
	}
}

// TestSetDiffIsOrderIndependent: two collectors may list the same namespaces in
// a different order. Reporting that as a change would make every diff noisy.
func TestSetDiffIsOrderIndependent(t *testing.T) {
	const base = `{"coverage": {"unprotectedNamespaces": {"items": ["a", "b", "c"]}}}`
	const cur = `{"coverage": {"unprotectedNamespaces": {"items": ["c", "a", "b"]}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 || res.Summary.Improvements != 0 {
		t.Errorf("reordering the same set was reported as a change")
	}
}

// TestCatalogFreeSpaceIsThreeWay: kdl-diff.sh only calls a free-space drop a
// regression when it lands below 20%, and CRITICAL below 10%. Grading every
// decrease a regression fails a CI gate on a healthy cluster whose catalog is
// simply filling up.
func TestCatalogFreeSpaceIsThreeWay(t *testing.T) {
	for _, tc := range []struct {
		base, cur int
		want      Kind
	}{
		{95, 85, KindNeutral},     // ordinary growth
		{95, 25, KindNeutral},     // still comfortable
		{40, 15, KindRegression},  // below 20%
		{40, 5, KindRegression},   // below 10%: critical
		{50, 60, KindImprovement}, // reclaimed
	} {
		doc := func(v int) string {
			return fmt.Sprintf(`{"catalog": {"pvcName": "catalog-pv-claim", "freeSpacePercent": %d}}`, v)
		}
		res := compare(t, doc(tc.base), doc(tc.cur))
		got := findings(res)["catalogFreeSpace"]
		if got.Kind != tc.want {
			t.Errorf("catalog %d%% → %d%%: kind = %q, want %q", tc.base, tc.cur, got.Kind, tc.want)
		}
	}
}

// TestAbsentCatalogIsNotAFullOne: a section the collector never gathered has
// freeSpacePercent 0, which reads as a catalog about to fail. Diffing it
// fabricates a CRITICAL regression out of a section nobody ran -- on exactly
// the shell-vs-Go comparison this package exists to make trustworthy.
func TestAbsentCatalogIsNotAFullOne(t *testing.T) {
	const base = `{"catalog": {"pvcName": "catalog-pv-claim", "size": "20Gi", "freeSpacePercent": 95}}`
	const cur = `{"kdlVersion": "2.2.0-go"}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: the catalog was never collected, not filled up", res.Summary.Regressions)
	}
}

// TestNodeCountIsNotAGate: adding a worker node is ordinary cluster growth and
// kdl-diff.sh does not gate on it. Calling it a regression is a correct number
// turned into a false claim.
func TestNodeCountIsNotAGate(t *testing.T) {
	const base = `{"license": {"nodeConsumption": {"current": 4, "limit": 25, "status": "OK", "assessed": true}}}`
	const cur = `{"license": {"nodeConsumption": {"current": 6, "limit": 25, "status": "OK", "assessed": true}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: node growth is not a regression", res.Summary.Regressions)
	}
	if _, ok := findings(res)["nodesConsumed"]; !ok {
		t.Error("the node count change must still be reported, just not gated on")
	}
}

// TestOneNewUnprotectedVMIsOneRegression: the exit code IS the regression
// count, so double-counting an event tells a CI gate two things broke when one
// did. This section reported the same VM twice, via a count delta and a set
// difference.
func TestOneNewUnprotectedVMIsOneRegression(t *testing.T) {
	const base = `{"virtualization": {"protection": {"unprotectedVMs": 0, "unprotectedVmList": []}}}`
	const cur = `{"virtualization": {"protection": {"unprotectedVMs": 1, "unprotectedVmList": ["ns/vm-a"]}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 1 {
		t.Errorf("regressions = %d, want 1 for one newly unprotected VM", res.Summary.Regressions)
	}
	if res.Summary.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1: the gate reads this number as a count", res.Summary.ExitCode)
	}
}

// TestLicenceRenewalIsAnImprovement: a licence going EXPIRED → VALID is the
// customer fixing the problem, which kdl-diff.sh reports as an improvement.
func TestLicenceRenewalIsAnImprovement(t *testing.T) {
	const base = `{"license": {"licenses": [{"id": "a", "status": "EXPIRED"}]}}`
	const cur = `{"license": {"licenses": [{"id": "a", "status": "VALID"}]}}`

	if got := compare(t, base, cur).Summary.Improvements; got != 1 {
		t.Errorf("improvements = %d, want 1: a renewed licence is an improvement", got)
	}
}

// TestConsumptionRecoveryIsAnImprovement: coming back under the node limit is
// likewise the problem being fixed.
func TestConsumptionRecoveryIsAnImprovement(t *testing.T) {
	const base = `{"license": {"nodeConsumption": {"current": 30, "limit": 25, "status": "EXCEEDED", "assessed": true}}}`
	const cur = `{"license": {"nodeConsumption": {"current": 20, "limit": 25, "status": "OK", "assessed": true}}}`

	if got := compare(t, base, cur).Summary.Improvements; got != 1 {
		t.Errorf("improvements = %d, want 1: back under the node limit is an improvement", got)
	}
}

// TestAbsentPolicyAnalysisIsNotZeroRedundancy: a report whose policy analysis
// was never computed has 0 redundant pairs. Diffing that against a real
// analysis invents a regression out of a section nobody ran.
func TestAbsentPolicyAnalysisIsNotZeroRedundancy(t *testing.T) {
	const base = `{"kdlVersion": "2.2.0-go"}`
	const cur = `{"policyAnalysis": {"summary": {"totalPolicies": 10, "redundantPairsGenuine": 3}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: the baseline never computed the analysis", res.Summary.Regressions)
	}
}

// TestUncollectedSectionIsNotDiffed is the fix for the worst class of finding
// this package can produce.
//
// A report whose producer never computed a section carries that section as a
// zero value, and the zero value of a licence list is "no licences". Diffing it
// against a real report announced "3 licence(s) removed" and "K10 disaster
// recovery disabled" -- two of the most alarming things this tool can say, both
// entirely false, and neither detectable from the section's own contents. The
// producer now declares what it did not compute, and the diff honours it.
func TestUncollectedSectionIsNotDiffed(t *testing.T) {
	const full = `{
	  "kdlVersion": "2.2.0",
	  "license": {"licenses": [{"id": "a", "status": "VALID"}, {"id": "b", "status": "VALID"}]},
	  "disasterRecovery": {"enabled": true},
	  "catalog": {"pvcName": "catalog-pv-claim", "freeSpacePercent": 95}
	}`
	// Same shape as a Go-collected report: the sections are absent AND declared.
	const partial = `{
	  "kdlVersion": "2.2.0-go",
	  "unpopulatedSections": ["license", "disasterRecovery", "catalog"]
	}`

	res := compare(t, full, partial)
	if res.Summary.Regressions != 0 {
		t.Errorf("regressions = %d, want 0: none of those sections was collected", res.Summary.Regressions)
		for _, s := range res.Sections {
			for _, f := range s.Findings {
				if f.Kind == KindRegression {
					t.Logf("  fabricated: %s: %s", s.Name, f.Message)
				}
			}
		}
	}

	// The reader must be told the sections were skipped, not left to assume
	// silence meant parity.
	for _, section := range []string{"license", "disasterRecovery", "catalog"} {
		f, ok := findings(res)[section]
		if !ok {
			t.Errorf("section %q was skipped without saying so", section)
			continue
		}
		if f.Kind != KindInfo {
			t.Errorf("section %q: kind = %q, want %q", section, f.Kind, KindInfo)
		}
	}
}

// TestUndeclaredAbsenceIsStillDiffed is the counterpart: a report that does NOT
// declare a section uncomputed is taken at its word. Skipping every empty
// section would be the opposite error -- a real licence removal would go
// unreported.
func TestUndeclaredAbsenceIsStillDiffed(t *testing.T) {
	const base = `{"license": {"licenses": [{"id": "a", "status": "VALID"}]}}`
	const cur = `{"license": {"licenses": []}}`

	if got := compare(t, base, cur).Summary.Regressions; got != 1 {
		t.Errorf("regressions = %d, want 1: an undeclared empty section is a real change", got)
	}
}

// TestUnprotectedVMCountGatesWithoutTheList: unprotectedVmList is omitempty and
// absent from every real report available, so gating on the list alone left a
// cluster whose unprotected VMs went 1 to 4 reporting "No change".
//
// The counterpart below proves the count is still not double-counted when the
// list IS present -- the two failures this section has had, in both directions.
func TestUnprotectedVMCountGatesWithoutTheList(t *testing.T) {
	const base = `{"virtualization": {"protection": {"unprotectedVMs": 1}}}`
	const cur = `{"virtualization": {"protection": {"unprotectedVMs": 4}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 1 {
		t.Errorf("regressions = %d, want 1: the count rose with no list to name them", res.Summary.Regressions)
	}
	if res.Summary.ExitCode == 0 {
		t.Error("exit code 0 for a cluster whose unprotected VM count quadrupled")
	}
}

// TestUnprotectedVMWithListIsStillOneRegression: naming the VMs must not turn
// one event into two regressions -- the exit code is read as a count.
func TestUnprotectedVMWithListIsStillOneRegression(t *testing.T) {
	const base = `{"virtualization": {"protection": {"unprotectedVMs": 0, "unprotectedVmList": []}}}`
	const cur = `{"virtualization": {"protection": {"unprotectedVMs": 1, "unprotectedVmList": ["ns/vm-a"]}}}`

	res := compare(t, base, cur)
	if res.Summary.Regressions != 1 {
		t.Errorf("regressions = %d, want exactly 1", res.Summary.Regressions)
	}
	// The VM must still be named, just not gated on twice.
	if f, ok := findings(res)["unprotectedVMs"]; !ok || !strings.Contains(f.Message, "ns/vm-a") {
		t.Error("the newly unprotected VM is no longer named")
	}
}

// TestSummaryModeKeepsSkippedSections: --summary is the mode a TAM runs for a
// quarterly review. Suppressing the "not compared" notes renders five unknown
// sections as a clean bill of health -- a silent false all-clear, which is the
// fabricated alarm's mirror image and just as wrong.
func TestSummaryModeKeepsSkippedSections(t *testing.T) {
	const full = `{"license": {"licenses": [{"id": "a", "status": "VALID"}]}, "disasterRecovery": {"enabled": true}}`
	const partial = `{"kdlVersion": "2.2.0-go", "unpopulatedSections": ["license", "disasterRecovery"]}`

	var buf bytes.Buffer
	if err := RenderHuman(&buf, compare(t, full, partial), false, true); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Licence", "Disaster Recovery", "not compared"} {
		if !strings.Contains(out, want) {
			t.Errorf("--summary output does not mention %q; a skipped section reads as no change:\n%s", want, out)
		}
	}
}

// TestPartiallyComputedSectionIsNotFabricated: policyAnalysis IS computed by
// the Go collector, but redundancy is not. Its structural zero read as
// "21 redundant pairs resolved" -- a TAM told the customer fixed something they
// never touched.
func TestPartiallyComputedSectionIsNotFabricated(t *testing.T) {
	const full = `{"policyAnalysis": {"summary": {"totalPolicies": 28, "redundantPairsGenuine": 21}}}`
	const partial = `{"policyAnalysis": {"summary": {"totalPolicies": 3, "redundantPairsGenuine": 0}},
	  "unpopulatedSections": ["policyAnalysis.summary.redundantPairsGenuine"]}`

	res := compare(t, full, partial)
	if res.Summary.Improvements != 0 {
		t.Errorf("improvements = %d, want 0: redundancy was never computed", res.Summary.Improvements)
	}
}

// TestNotAssessedCheckIsNotARegression: KDL.sh writes NOT_ASSESSED when RBAC
// denied the read a check needs. A customer who ran with full RBAC one quarter
// and restricted RBAC the next would otherwise get a regression that is purely
// a permissions change -- the misreporting that value exists to prevent.
func TestNotAssessedCheckIsNotARegression(t *testing.T) {
	const base = `{"bestPractices": {"namespaceProtection": "COMPLETE"}}`
	const cur = `{"bestPractices": {"namespaceProtection": "NOT_ASSESSED"}}`

	if got := compare(t, base, cur).Summary.Regressions; got != 0 {
		t.Errorf("regressions = %d, want 0: the check was not assessed, not failed", got)
	}
}
