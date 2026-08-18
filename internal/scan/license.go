package scan

// The licence section: what the customer is entitled to, and whether the cluster
// fits inside it.
//
// This is the only section whose source is Secrets read without a label
// selector, and the reason is that there is nothing to select on: K10 licence
// secrets carry no distinguishing label, and their names vary across installs
// and renewals (k10-license, k10-trial-license, renamed variants). Only secrets
// whose name contains "license" are looked at, only the `license` key is
// decoded, and nothing from the payload reaches the report except the fields
// below -- never the raw value.
//
// Every verdict here is gated on the node count being real. A denied node
// listing yields zero, and zero nodes against any limit reads as a licence
// comfortably within its entitlement, which is the reassuring answer and the
// wrong one.

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Licence types, in the order they must be tested. TRIAL is first, on two
// independent signals, so a trial whose customer name also contains "starter"
// can never fall through to STARTER -- and STARTER matches the customer name
// exactly rather than as a substring, for the same reason.
const (
	licenseTrial      = "TRIAL"
	licenseStarter    = "STARTER"
	licenseEnterprise = "ENTERPRISE"
)

// Overall licence-section statuses, as KDL.sh spells them.
const (
	licenseNotFound    = "NOT_FOUND"
	licenseUnparseable = "UNPARSEABLE"
	licensePresent     = "PRESENT"
)

// buildLicense parses the licence secrets and reconciles them against what the
// cluster actually consumes.
func buildLicense(res Result, r *kdl.Report, now time.Time) {
	secrets := res.Get("licenseSecrets")

	var (
		parsed      []kdl.LicenseEntry
		unparseable []kdl.LicenseUnparseable
		secretCount int
	)
	for _, o := range secrets.Items {
		if !strings.Contains(strings.ToLower(name(o)), "license") {
			continue
		}
		secretCount++
		payload, ok := licensePayload(o)
		if !ok {
			unparseable = append(unparseable, kdl.LicenseUnparseable{
				Secret: name(o), Reason: "no .data.license field",
			})
			continue
		}
		entry, ok := parseLicense(name(o), payload, now)
		if !ok {
			// The name match is deliberately broad, so the payload signature is
			// the real guard: a secret named "license-something" that carries no
			// licence is recorded and skipped rather than mis-parsed as one.
			unparseable = append(unparseable, kdl.LicenseUnparseable{
				Secret: name(o), Reason: "missing customerName/id/product signature",
			})
			continue
		}
		parsed = append(parsed, entry)
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].Secret < parsed[j].Secret })
	sort.Slice(unparseable, func(i, j int) bool { return unparseable[i].Secret < unparseable[j].Secret })

	switch {
	case secretCount == 0 && len(parsed) == 0:
		r.License.Status = licenseNotFound
	case len(parsed) == 0:
		r.License.Status = licenseUnparseable
	default:
		r.License.Status = licensePresent
	}
	r.License.SecretCount = secretCount
	r.License.ParseableCount = len(parsed)
	r.License.Licenses = parsed
	r.License.Unparseable = unparseable
	r.License.NearestExpiry = nearestExpiry(parsed)

	buildNodeEntitlement(res, r, parsed)
}

// licensePayload decodes the licence blob. Secret data arrives base64-encoded in
// the API's JSON, exactly once.
func licensePayload(o unstructured.Unstructured) (string, bool) {
	encoded, ok := str(o.Object, "data", "license")
	if !ok || encoded == "" {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// parseLicense reads the YAML-ish licence payload.
//
// It is parsed line by line rather than with a YAML library, matching KDL.sh: the
// payload is a flat set of key/value lines plus one indented block, and the value
// is everything after the FIRST colon -- ISO timestamps embed their own colons
// and must not be truncated at them.
func parseLicense(secret, payload string, now time.Time) (kdl.LicenseEntry, bool) {
	top := map[string]string{}
	nested := map[string]string{}
	for _, line := range strings.Split(payload, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		v := strings.Trim(strings.TrimSpace(value), `"'`)
		// Indentation is what separates restrictions.nodes from a same-named
		// top-level field, so the two namespaces are kept apart.
		if key != trimmedKey {
			nested[strings.ToLower(trimmedKey)] = v
			continue
		}
		top[strings.ToLower(trimmedKey)] = v
	}

	entry := kdl.LicenseEntry{
		Secret:    secret,
		Customer:  top["customername"],
		ID:        top["id"],
		Product:   top["product"],
		DateStart: orNAValue(top["datestart"]),
		DateEnd:   orNAValue(top["dateend"]),
		Nodes:     "unlimited",
		Features:  "-",
	}
	if entry.Customer == "" || entry.ID == "" || entry.Product == "" {
		return kdl.LicenseEntry{}, false
	}
	if n := nested["nodes"]; n != "" {
		entry.Nodes = n
	}
	if f := top["features"]; f != "" && f != "null" {
		entry.Features = f
	}
	entry.Type = licenseType(entry.ID, entry.Customer)
	entry.DaysRemaining, entry.Status = expiry(entry.DateEnd, now)
	return entry, true
}

// licenseType derives the entitlement class. Order matters and is the whole
// point of the function: see the constants above.
func licenseType(id, customer string) string {
	lowerID, lowerCustomer := strings.ToLower(id), strings.ToLower(customer)
	switch {
	case strings.HasPrefix(lowerID, "trial-") || strings.Contains(lowerCustomer, "trial"):
		return licenseTrial
	case lowerCustomer == "starter-license" || strings.HasPrefix(lowerID, "starter-"):
		return licenseStarter
	default:
		// A licence that is neither trial nor starter is commercial: its id is a
		// bare UUID carrying no type prefix, so it is ENTERPRISE rather than
		// UNKNOWN.
		return licenseEnterprise
	}
}

// expiry computes days remaining and the per-licence status. A licence whose end
// date cannot be read is UNKNOWN rather than VALID: an unreadable expiry is not
// evidence of a live licence.
func expiry(dateEnd string, now time.Time) (int, string) {
	if dateEnd == "" || dateEnd == naValue || dateEnd == "null" {
		return 0, "UNKNOWN"
	}
	// K10 writes fractional seconds on some releases, which RFC 3339 parsing
	// handles but the shell had to strip explicitly.
	end, err := time.Parse(time.RFC3339, dateEnd)
	if err != nil {
		return 0, "UNKNOWN"
	}
	days := int(end.Sub(now).Hours() / 24)
	if days < 0 {
		return days, "EXPIRED"
	}
	return days, "VALID"
}

// nearestExpiry is the licence running out first, which is the one figure a TAM
// needs before a renewal conversation.
func nearestExpiry(entries []kdl.LicenseEntry) kdl.LicenseNearestExpiry {
	var soonest *kdl.LicenseEntry
	for i := range entries {
		if entries[i].Status == "UNKNOWN" {
			continue
		}
		if soonest == nil || entries[i].DaysRemaining < soonest.DaysRemaining {
			soonest = &entries[i]
		}
	}
	if soonest == nil {
		return kdl.LicenseNearestExpiry{}
	}
	return kdl.LicenseNearestExpiry{
		Secret:        soonest.Secret,
		DateEnd:       soonest.DateEnd,
		DaysRemaining: soonest.DaysRemaining,
	}
}

// buildNodeEntitlement reconciles the node limits in the secrets against the
// limit K10 itself reports, and both against the cluster's node count.
//
// The paid/trial split exists because a long-lived trial licence must not inflate
// the headline entitlement: summing a trial limit with a paid one produces a
// figure the deployment is not entitled to, and the customer discovers that at
// renewal.
func buildNodeEntitlement(res Result, r *kdl.Report, entries []kdl.LicenseEntry) {
	var (
		fromSecrets, paidTotal       int
		hasUnlimited, paidUnlimited  bool
		trialPresent, anyPaidLicence bool
	)
	for _, e := range entries {
		nodes, numeric := licenceNodes(e.Nodes)
		isTrial := e.Type == licenseTrial
		if isTrial {
			trialPresent = true
		} else {
			anyPaidLicence = true
		}
		if !numeric {
			hasUnlimited = true
			if !isTrial {
				paidUnlimited = true
			}
			continue
		}
		fromSecrets += nodes
		if !isTrial {
			paidTotal += nodes
		}
	}

	reportLimit, reportNodeCount := licensingFromReport(res)

	agg := kdl.LicenseNodeLimitAggregate{
		FromSecrets:  fromSecrets,
		FromReportCR: reportLimit,
		HasUnlimited: hasUnlimited,
	}
	// A mismatch is only meaningful between two numbers. An unlimited licence has
	// no count to disagree with.
	if reportLimit.Numeric && !hasUnlimited {
		agg.Mismatch = reportLimit.Count != fromSecrets
	}
	paidLimit := entitlement(paidUnlimited, anyPaidLicence, paidTotal)
	agg.FromPaidSecrets = &paidLimit
	r.License.NodeLimitAggregate = agg

	// The node count has two sources, and they are not equally trustworthy in the
	// same way. K10's own report is legitimate without list-nodes permission --
	// K10 counted them itself -- so only the live listing is compromised when that
	// specific read was refused.
	nodes := res.Get("nodes")
	current, assessed := reportNodeCount, true
	if current == 0 {
		current = len(nodes.Items)
		assessed = nodes.OK()
	}

	consumption := kdl.LicenseNodeConsumption{
		Current:      current,
		Limit:        effectiveLimit(hasUnlimited, reportLimit, len(entries), fromSecrets),
		Assessed:     &assessed,
		PaidLimit:    &paidLimit,
		TrialPresent: trialPresent,
	}
	consumption.Status, consumption.PaidStatus, consumption.TrialInflating =
		consumptionStatus(consumption, paidLimit, trialPresent, assessed)
	r.License.NodeConsumption = consumption
}

// licenceNodes reads a licence's node cap. A non-numeric value is "unlimited":
// that is the word KDL emits, and it must never be compared against a count.
func licenceNodes(nodes string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(nodes))
	if err != nil {
		return 0, false
	}
	return n, true
}

// entitlement builds a NodeLimit from a total. "none" is not zero: it means no
// licence of that class exists at all, which is a different conversation from an
// entitlement of zero nodes.
func entitlement(unlimited, anyLicence bool, total int) kdl.NodeLimit {
	switch {
	case unlimited:
		return kdl.NodeLimit{Text: "unlimited"}
	case anyLicence:
		return kdl.NodeLimit{Count: total, Numeric: true}
	default:
		return kdl.NodeLimit{Text: "none"}
	}
}

// effectiveLimit is the cap the cluster is actually measured against: unlimited
// wins, then K10's own reported limit, then the sum from the secrets.
func effectiveLimit(hasUnlimited bool, reportLimit kdl.NodeLimit, licenceCount, fromSecrets int) kdl.NodeLimit {
	switch {
	case hasUnlimited:
		return kdl.NodeLimit{Text: "unlimited"}
	case reportLimit.Numeric:
		return reportLimit
	case licenceCount > 0:
		return kdl.NodeLimit{Count: fromSecrets, Numeric: true}
	default:
		// No licence found at all. Claiming a limit of zero would report every
		// cluster without a readable licence as over its entitlement.
		return kdl.NodeLimit{Text: "unlimited"}
	}
}

// consumptionStatus grades the node count against both entitlements.
//
// Everything short-circuits to NOT_ASSESSED when the count is not real. A
// verdict either way over a node count nobody could read is the misleading
// zero this tool exists to avoid: OK would reassure, EXCEEDED would alarm, and
// both would be about data never seen.
func consumptionStatus(c kdl.LicenseNodeConsumption, paidLimit kdl.NodeLimit,
	trialPresent, assessed bool) (status, paidStatus string, trialInflating bool) {

	if !assessed {
		return kdl.StatusNotAssessed, kdl.StatusNotAssessed, false
	}

	status = statusOK
	if c.Limit.Numeric && c.Limit.Count > 0 && c.Current > c.Limit.Count {
		status = "EXCEEDED"
	}

	paidStatus = statusOK
	switch {
	case paidLimit.Text == "unlimited":
		// Any count fits.
	case paidLimit.Text == "none":
		// No paid licence at all: whatever is running relies on a trial.
		paidStatus = "NO_PAID_LICENSE"
		trialInflating = trialPresent && c.Current > 0
	case paidLimit.Numeric && paidLimit.Count > 0 && c.Current > paidLimit.Count:
		paidStatus = "EXCEEDS_PAID"
		// "Inflating" only when a trial licence is what keeps the headline green.
		trialInflating = trialPresent
	}
	return status, paidStatus, trialInflating
}

// licensingFromReport reads the node limit and count K10 published in its own
// newest report. Both are absent until the system reports policy has run.
func licensingFromReport(res Result) (kdl.NodeLimit, int) {
	var newest map[string]any
	newestAt := ""
	for _, o := range res.Items("k10Reports") {
		licensing := mapAt(o.Object, "results", "licensing")
		if licensing == nil {
			continue
		}
		if ts := creationTimestamp(o); ts >= newestAt {
			newest, newestAt = licensing, ts
		}
	}
	if newest == nil {
		return kdl.NodeLimit{Absent: true}, 0
	}

	limit := kdl.NodeLimit{Absent: true}
	switch v := newest["nodeLimit"].(type) {
	case string:
		if v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = kdl.NodeLimit{Count: n, Numeric: true}
			} else {
				limit = kdl.NodeLimit{Text: v}
			}
		}
	default:
		if n, ok := toNumber(v); ok {
			limit = kdl.NodeLimit{Count: int(n), Numeric: true}
		}
	}
	count := 0
	if n, ok := toNumber(newest["nodeCount"]); ok {
		count = int(n)
	}
	return limit, count
}

func orNAValue(s string) string {
	if strings.TrimSpace(s) == "" {
		return naValue
	}
	return s
}
