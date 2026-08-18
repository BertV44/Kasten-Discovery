package scan

import (
	"encoding/base64"
	"testing"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// licenseSecret builds a K10 licence secret. The payload is the flat key/value
// text K10 stores, base64-encoded once by the API's secret serialisation.
func licenseSecret(name, payload string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": name, "namespace": "kasten-io"},
		"data": map[string]any{
			"license": base64.StdEncoding.EncodeToString([]byte(payload)),
		},
	}}
}

func nodeObjects(n int) []unstructured.Unstructured {
	out := make([]unstructured.Unstructured, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, obj("Node", "node-"+string(rune('a'+i)), nil))
	}
	return out
}

// enterpriseLicence is a payload with the full signature and an indented
// restrictions block, which is where the node cap lives.
const enterpriseLicence = `id: 7f3c2b1a-0000-4000-8000-000000000001
customerName: Acme Corp
product: K10
dateStart: 2026-01-01T00:00:00Z
dateEnd: 2027-01-01T00:00:00Z
restrictions:
  nodes: 10
features: null
`

// TestLicenceParsesTheFullSignature, and keeps the timestamp intact: the value is
// everything after the FIRST colon, because an ISO timestamp embeds its own.
func TestLicenceParsesTheFullSignature(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {licenseSecret("k10-license", enterpriseLicence)},
		"nodes":   nodeObjects(4),
	})

	if r.License.Status != licensePresent {
		t.Fatalf("status = %q, want %q", r.License.Status, licensePresent)
	}
	if r.License.ParseableCount != 1 || len(r.License.Licenses) != 1 {
		t.Fatalf("licences = %+v, want exactly one parsed", r.License.Licenses)
	}
	l := r.License.Licenses[0]
	if l.Customer != "Acme Corp" || l.ID != "7f3c2b1a-0000-4000-8000-000000000001" {
		t.Errorf("licence = %+v, want the customer and id read out", l)
	}
	if l.DateEnd != "2027-01-01T00:00:00Z" {
		t.Errorf("dateEnd = %q, want the full timestamp: the value is everything after the first colon", l.DateEnd)
	}
	if l.Nodes != "10" {
		t.Errorf("nodes = %q, want 10 from the indented restrictions block", l.Nodes)
	}
	if l.Type != licenseEnterprise {
		t.Errorf("type = %q, want %q: a bare UUID carries no type prefix", l.Type, licenseEnterprise)
	}
	if l.Status != "VALID" {
		t.Errorf("status = %q, want VALID: the licence runs to 2027", l.Status)
	}
	if l.Features != "-" {
		t.Errorf("features = %q, want the placeholder for a null value", l.Features)
	}
}

// TestTrialIsTestedBeforeStarter: a trial whose customer name also contains
// "starter" must never fall through to STARTER, which is why the order is fixed.
func TestTrialIsTestedBeforeStarter(t *testing.T) {
	for _, tc := range []struct {
		id, customer, want string
	}{
		{"trial-123", "starter-license", licenseTrial},
		{"abc-123", "Acme Trial Eval", licenseTrial},
		{"starter-9", "Someone", licenseStarter},
		{"abc-123", "starter-license", licenseStarter},
		// A substring match on "starter" would misclassify this one.
		{"abc-123", "Starterco Industries", licenseEnterprise},
		{"abc-123", "Acme Corp", licenseEnterprise},
	} {
		if got := licenseType(tc.id, tc.customer); got != tc.want {
			t.Errorf("licenseType(%q, %q) = %q, want %q", tc.id, tc.customer, got, tc.want)
		}
	}
}

// TestUnparseableSecretIsRecordedNotMisparsed: the name match is deliberately
// broad, so the payload signature is the real guard -- a secret named
// "…license…" that is not one must be recorded and skipped.
func TestUnparseableSecretIsRecordedNotMisparsed(t *testing.T) {
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {
			licenseSecret("k10-license", enterpriseLicence),
			licenseSecret("my-license-signing-key", "someKey: not-a-licence\n"),
			// A secret with no license key at all.
			unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]any{"name": "old-license-backup", "namespace": "kasten-io"},
				"data":     map[string]any{"other": "eHh4"},
			}},
			// And a secret that is not licence-named at all: never looked at.
			unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]any{"name": "s3-credentials", "namespace": "kasten-io"},
				"data":     map[string]any{"license": "eHh4"},
			}},
		},
		"nodes": nodeObjects(2),
	})

	if r.License.SecretCount != 3 {
		t.Errorf("secretCount = %d, want 3 licence-named secrets (s3-credentials is not one)",
			r.License.SecretCount)
	}
	if r.License.ParseableCount != 1 {
		t.Errorf("parseableCount = %d, want 1", r.License.ParseableCount)
	}
	if len(r.License.Unparseable) != 2 {
		t.Fatalf("unparseable = %+v, want both non-licences recorded with a reason",
			r.License.Unparseable)
	}
	for _, u := range r.License.Unparseable {
		if u.Reason == "" {
			t.Errorf("unparseable entry %q has no reason; the count alone is unactionable", u.Secret)
		}
	}
}

// TestTrialDoesNotInflateThePaidEntitlement is the finding the paid split exists
// for: summing a trial cap with a paid one produces a figure the deployment is
// not entitled to, and the customer finds out at renewal.
func TestTrialDoesNotInflateThePaidEntitlement(t *testing.T) {
	trial := `id: trial-999
customerName: Acme Trial
product: K10
dateEnd: 2027-01-01T00:00:00Z
restrictions:
  nodes: 50
`
	paid := `id: 7f3c2b1a-0000-4000-8000-000000000001
customerName: Acme Corp
product: K10
dateEnd: 2027-01-01T00:00:00Z
restrictions:
  nodes: 5
`
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {
			licenseSecret("k10-trial-license", trial),
			licenseSecret("k10-license", paid),
		},
		"nodes": nodeObjects(8),
	})

	nc := r.License.NodeConsumption
	if nc.Current != 8 {
		t.Fatalf("current = %d, want 8 nodes", nc.Current)
	}
	// 50 + 5 = 55 total, so the headline fits and reports OK.
	if nc.Status != statusOK {
		t.Errorf("status = %q, want OK: 8 nodes fit inside the combined 55", nc.Status)
	}
	// But the paid entitlement is 5, and that is the one that survives the trial.
	if nc.PaidLimit == nil || !nc.PaidLimit.Numeric || nc.PaidLimit.Count != 5 {
		t.Errorf("paidLimit = %+v, want 5: the trial's 50 nodes are not an entitlement", nc.PaidLimit)
	}
	if nc.PaidStatus != "EXCEEDS_PAID" {
		t.Errorf("paidStatus = %q, want EXCEEDS_PAID: 8 nodes on a 5-node paid licence", nc.PaidStatus)
	}
	if !nc.TrialPresent || !nc.TrialInflating {
		t.Errorf("trialPresent/trialInflating = %v/%v, want both true: a trial is what keeps the headline green",
			nc.TrialPresent, nc.TrialInflating)
	}
}

// TestUnlimitedLicenceIsNotALargeNumber: it must never be compared against a
// count, which is why NodeLimit is not an int.
func TestUnlimitedLicenceIsNotALargeNumber(t *testing.T) {
	unlimited := `id: 7f3c2b1a-0000-4000-8000-000000000001
customerName: Acme Corp
product: K10
dateEnd: 2027-01-01T00:00:00Z
`
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {licenseSecret("k10-license", unlimited)},
		"nodes":   nodeObjects(9),
	})

	if got := r.License.Licenses[0].Nodes; got != "unlimited" {
		t.Errorf("nodes = %q, want unlimited when no restriction is stated", got)
	}
	if !r.License.NodeLimitAggregate.HasUnlimited {
		t.Error("hasUnlimited = false with an uncapped licence")
	}
	limit := r.License.NodeConsumption.Limit
	if limit.Numeric || limit.Text != "unlimited" {
		t.Errorf("limit = %+v, want the word rather than a count", limit)
	}
	if got := r.License.NodeConsumption.Status; got != statusOK {
		t.Errorf("status = %q, want OK: any count fits an unlimited licence", got)
	}
	if r.License.NodeLimitAggregate.Mismatch {
		t.Error("mismatch = true against an unlimited licence; there is no count to disagree with")
	}
}

// TestExpiredLicenceIsReportedAsExpired, and the nearest expiry is the one a TAM
// needs before a renewal conversation.
func TestExpiredLicenceIsReportedAsExpired(t *testing.T) {
	expired := `id: 7f3c2b1a-0000-4000-8000-000000000001
customerName: Acme Corp
product: K10
dateEnd: 2026-01-01T00:00:00Z
restrictions:
  nodes: 10
`
	later := `id: 7f3c2b1a-0000-4000-8000-000000000002
customerName: Acme Corp
product: K10
dateEnd: 2030-01-01T00:00:00Z
restrictions:
  nodes: 10
`
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"secrets": {
			licenseSecret("k10-license-old", expired),
			licenseSecret("k10-license-new", later),
		},
		"nodes": nodeObjects(2),
	})

	byName := map[string]kdl.LicenseEntry{}
	for _, l := range r.License.Licenses {
		byName[l.Secret] = l
	}
	if got := byName["k10-license-old"]; got.Status != "EXPIRED" || got.DaysRemaining >= 0 {
		t.Errorf("old licence = %+v, want EXPIRED with negative days remaining", got)
	}
	if got := byName["k10-license-new"].Status; got != "VALID" {
		t.Errorf("new licence status = %q, want VALID", got)
	}
	if got := r.License.NearestExpiry.Secret; got != "k10-license-old" {
		t.Errorf("nearestExpiry = %q, want the licence running out first", got)
	}
}

// TestDeniedLicenceReadIsDeclared: "no licence installed" and "we could not look"
// lead opposite ways, and the section's own contents cannot tell them apart.
func TestDeniedLicenceReadIsDeclared(t *testing.T) {
	res := collect(t, &fakeReader{errs: map[string]error{"secrets": forbidden("secrets")}})
	res.CollectedAt = testNow
	r := Build(res)

	if !r.NotCollected("license") {
		t.Error("license is not declared unpopulated, but the secret read was denied")
	}
}

// TestCatalogFreeSpaceIsNeverInvented: the figure comes from running df inside
// the catalog pod, and a pod exec is a write verb this collector does not have.
// Zero percent free is the most alarming line the section can carry.
func TestCatalogFreeSpaceIsNeverInvented(t *testing.T) {
	pvc := func(name string, labels map[string]any, size string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata":   map[string]any{"name": name, "namespace": "kasten-io", "labels": labels},
			"status":     map[string]any{"capacity": map[string]any{"storage": size}},
		}}
	}
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"persistentvolumeclaims": {pvc("catalog-pv-claim", map[string]any{"component": "catalog"}, "20Gi")},
	})

	if r.Catalog.PVCName != "catalog-pv-claim" || r.Catalog.Size != "20Gi" {
		t.Errorf("catalog = %+v, want the labelled claim and its bound size", r.Catalog)
	}
	if r.Catalog.FreeSpacePercent != nil || r.Catalog.UsedPercent != nil {
		t.Errorf("catalog percentages = %v/%v, want null: measuring them needs a pod exec",
			r.Catalog.FreeSpacePercent, r.Catalog.UsedPercent)
	}
	if !r.NotCollected("catalog.freeSpacePercent") {
		t.Error("catalog.freeSpacePercent is not declared uncomputed, so a consumer reads null as zero")
	}
	// The rest of the section is real, so it must stay comparable.
	if r.NotCollected("catalog") {
		t.Error("the whole catalog section is declared uncomputed; only the free-space figure is missing")
	}
}

// TestDataUsageNormalisesEveryQuantityUnit: stripping the suffix and summing the
// numbers made a byte-valued PVC come out as ~9.7e11 GiB.
func TestDataUsageNormalisesEveryQuantityUnit(t *testing.T) {
	pvc := func(name, size string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata":   map[string]any{"name": name, "namespace": "apps"},
			"spec": map[string]any{"resources": map[string]any{
				"requests": map[string]any{"storage": size}}},
		}}
	}
	r := buildAt(t, map[string][]unstructured.Unstructured{
		"persistentvolumeclaims": {
			pvc("a", "10Gi"),
			pvc("b", "2048Mi"),     // 2 GiB
			pvc("c", "1073741824"), // 1 GiB in raw bytes
			pvc("d", "1Ti"),        // 1024 GiB
		},
	})

	if r.DataUsage.TotalPVCs != 4 {
		t.Errorf("totalPvcs = %d, want 4", r.DataUsage.TotalPVCs)
	}
	if got := r.DataUsage.TotalCapacityGi; got != 1037 {
		t.Errorf("totalCapacityGi = %d, want 1037 (10 + 2 + 1 + 1024)", got)
	}
}

// TestExportStorageSaysWhyItIsAbsent: "0 B" and "the reporting policy has never
// run" lead to completely different conversations.
func TestExportStorageSaysWhyItIsAbsent(t *testing.T) {
	absent := buildAt(t, map[string][]unstructured.Unstructured{})
	if got := absent.DataUsage.ExportStorage.DataSource; got != "none" {
		t.Errorf("dataSource = %q, want none", got)
	}
	if got := absent.DataUsage.ExportStorage.Display; got == "0 B" {
		t.Error("export storage displays 0 B where no report exists; that reads as an empty export target")
	}

	report := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "reporting.kio.kasten.io/v1alpha1",
		"kind":       "Report",
		"metadata": map[string]any{
			"name": "r1", "namespace": "kasten-io",
			"creationTimestamp": ago(0),
		},
		"results": map[string]any{"storage": map[string]any{"objectStorage": map[string]any{
			"physicalBytes": int64(1073741824),
			"logicalBytes":  int64(2147483648),
		}}},
	}}
	present := buildAt(t, map[string][]unstructured.Unstructured{"reports": {report}})

	es := present.DataUsage.ExportStorage
	if es.DataSource != "reports" || es.Display != "1.0 GiB" {
		t.Errorf("exportStorage = %+v, want 1.0 GiB from the report", es)
	}
	if got := present.DataUsage.Deduplication.Display; got != "2.0x" {
		t.Errorf("dedup = %q, want 2.0x (logical / physical)", got)
	}
}
