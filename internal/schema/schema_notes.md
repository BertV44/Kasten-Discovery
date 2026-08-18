# Schema notes

How `report.go` was produced, what is trustworthy in it, and what is not.

## Provenance

`report.go` was **generated** by `genschema.py` from a real anonymised cluster
report (`discovery-dev2.0-cluster-anon.json`, KDL 2.0) and then **hand-refined**.
It was not transcribed from `KDL.sh` by eye.

```bash
python3 go/internal/schema/genschema.py discovery-dev2.0-cluster-anon.json > go/internal/schema/report.go
```

Regenerating overwrites every hand refinement listed below. Regenerate only to
compare against the current file, then port the hand edits back.

The generator merges keys across **all** elements of every array, so a field
missing from some elements is detected and tagged `omitempty` with a note saying
how many samples lacked it. Numbers are `int` unless a fractional value was
observed anywhere.

> **The source sample is not in the repository.** `.gitignore:11` excludes
> `discovery-*.json`, so `discovery-dev2.0-cluster-anon.json` exists only on the
> machine where this was generated. On a fresh clone every fixture-backed test
> **skips** rather than fails, and phase 1 has no committed baseline to validate
> the renderer against. Decide deliberately whether to commit an anonymised
> fixture (say `go/testdata/`) — it is customer-derived data in a public repo, so
> it is not a decision to take by accident. Until then, pass `KDL_FIXTURE`.

### Objects keyed by arbitrary data

`coverage.namespacesInventory[].labels` is a `map[string]string`, not a struct.
The first generator run turned the 39 label keys of one cluster into struct
fields — including OLM operator-group UUIDs — which would not even compile, since
Kubernetes label keys contain `/`. The generator now detects such keys and emits
a map. Worth remembering when a new object shows up: **if the keys are data, the
type is a map.**

## Hand-written, not generated

| What | Why |
|---|---|
| `selector.go` in full | `policies.items[].selector` is polymorphic: the string `"all"` or an object. The generator could only type it `json.RawMessage`, which loses the distinction. |
| `KastenCompatibility`, `RBACLimited` | Added by KDL 2.2.0, so absent from the 2.0 source sample. Read off `KDL.sh`'s emitter. |
| `PoliciesItem.Scope`, `.Exports` | Same: 2.2.0 additions (`#kasten-v9`). |
| `PolicyExport`, `PoliciesAdditionalExport`(`Item`) | Kasten 9.0 additional export. |
| `Policies.AdditionalExport` | 2.2.0. |
| `Profiles.ImmutableCountTotal`, `.VBRCount`, `.VBRHardenedCount`, `.VeeamVaultCount` | 2.2.0. |
| `ProfilesItem.LocationType`, `.VBRRepoName`, `.VBRRepoType`, `.VBRImmutable` | 2.2.0. |
| `Hourly` on both retention structs | **A valid Kasten retention key that neither source sample exercised.** KDL 2.2.0 added it to `KDL.sh`'s console output, which had been dropping it on `@hourly` policies. (The HTML renderer was never affected — it walks the retention object generically.) Either way, inferring the tier list from a sample would have missed it. |
| `nodeConsumption.assessed` (2.1.1) | Without it the renderer printed "0 / 0" for a node count that RBAC had denied — the exact misleading zero `KDL.sh` goes out of its way to avoid. |
| `policyExclusions.byPolicy[].matchedNamespaces` (2.2.0) | Sibling of `patterns`, and `patterns` is a flat `[]string`, not the matchExpression this file first assumed. Both were wrong until a pass over the emitter caught them. |
| `StuckActionItem`, `OrphanedRestorePointItem`, `ProfileValidationItem.Error` | Typed from the emitter, not from a sample: every available report comes from a healthy cluster, so all three lists are empty in both. While they were `json.RawMessage` they type-checked and were **unrenderable**, which is how three unhealthy-cluster tables silently rendered as a bare count. |
| `RetentionAnalysisSnapshotRetentionHighItem` | Same story, same fix: `{name, max}` per the emitter. Both samples come from clusters inside the threshold, so the list is empty in each, and the section rendered a count with no way to say which policies. |
| `PolicyRunStatsLastRunEntry.Duration` → `*int` | `KDL.sh` emits `null` when a run recorded no start or end time. As an `int` that decoded to `0`, which is a run that finished instantly rather than one whose duration is unknown. |
| `LicenseUnparseable` | `{secret, reason}` per the emitter. Both samples come from clusters whose licences all parsed, so the list is empty in each — and while it was raw, a cluster whose licence could not be read showed a parseable count below its secret count with no way to say which secret, or why. |
| `Catalog.FreeSpacePercent`/`.UsedPercent` → `*int` | `KDL.sh` emits `null` when it could not run `df` in the catalog pod. As `int` that decoded to `0`, and 0% free is the most alarming line the section carries. The Go collector never fills them at all: a pod exec is a create against `pods/exec`, which the read-only Reader has no verb for. |
| `RansomwareProfileSkippingTLS` | `{name}` per the emitter. Both samples come from clusters that verify TLS, so the list is empty in each — and while it was raw, the pillar could show a 0/5 deduction without ever naming the profile that caused it. |
| `MultiCluster.PrimaryName`/`.ClusterID`, `K10ConfigurationSecurityEncryption.Details`, `…AuditLogging.Targets`, `K10ConfigurationSecurity.CustomCACertificate`, `K10ConfigurationPersistence.StorageClass`, `K10ConfigurationNonDefaultSettings.Items`, `K10Configuration.ClusterName` | All `*string` per the emitter, and all null in both samples because both come from standalone clusters with default security settings. Every one of them was unrendered while raw: the multi-cluster section showed a secondary with no primary, the security block never named the CA bundle or where the audit trail goes, and the tuned-settings count — the one line that makes four tables of numbers readable — was missing entirely. `NonDefaultSettings.Items` is worth singling out: it is **one comma-separated string**, not a list, because `KDL.sh` builds it by concatenation. |

The 2.2.0 sections are **pointers** on purpose: `nil` means "the report came from
an older KDL", which is not the same as "the section is empty". A renderer that
conflates the two will report a Kasten 9.0 feature as absent on a 2.1 report.

## Not verified — needs a report that exercises them

These 5 fields were `null` or an empty list in **both** available samples, so
their type is a guess and they are kept as `json.RawMessage` rather than typed
wrongly. Each one is a small, isolated task: get a report from a cluster that
exercises the field, look at the value, replace the type.

| Struct | Field |
|---|---|
| `PolicyPresetsItem` | `frequency` |
| `PolicyPresetsItem` | `retention` |
| `PolicyAnalysis` | `unresolvablePolicies` |
| `VolumeSnapshotClassesCSIDriversWithoutVSC` | `drivers` |
| `ProfilesItem` | `protectionPeriod` |

**`json.RawMessage` is not a free pass.** A field left raw type-checks but cannot
be rendered, so the section that needs it silently degrades to a count. That is
exactly how the stuck-actions, orphaned-restore-point and profile-validation
tables went missing. When the emitter says what the shape is, type it from the
emitter and note that no sample confirmed it — do not leave it raw.

Beyond this list, both samples are KDL **2.0 and 2.0.2**. Everything added in
2.1.x and 2.2.0 — the compatibility block, restricted-RBAC reporting, the paid
licence split, dual export, the 9.0 VM selectors, snapshot consistency, policy
exclusions — is modelled from reading `KDL.sh` and is **exercised only by
synthetic reports in the tests**. A single real 2.2.0 report would retire most of
this caveat.

## A wrong type is worse than a raw one

`NodeLimit` exists because four licence fields were typed `int` and KDL emits the
words `"unlimited"` and `"none"` in them (`KDL.sh` writes
`($limit | tonumber? // $limit)`, which falls back to the string). The result was
not a wrong figure but a **hard decode failure of the entire report**, and it was
never version-specific: `EFFECTIVE_LIMIT="unlimited"` predates v2.0.0, so any
cluster with an unlimited licence broke the renderer.

That is the mirror image of the `json.RawMessage` problem above. Both come from
inferring a type from samples that never exercised the field:

- too loose (`json.RawMessage`) → the field silently cannot be rendered;
- too tight (`int` for a value that can be a word) → nothing renders at all.

When the emitter shows a `tonumber? // …` fallback, or any `//` default whose two
branches differ in type, the field is a union and must be modelled as one.

## Finding drift automatically

`TestStrictDecode` decodes with `DisallowUnknownFields`, so any key the structs
do not model is a test failure naming the key. Point it at a newer report:

```bash
KDL_FIXTURE=/path/to/newer-report.json go test ./internal/schema/
```

Same check from the CLI, with a summary of what was decoded:

```bash
go run ./cmd/kdl validate -in /path/to/report.json
```

`TestRoundTripKeepsData` re-encodes the decoded report and fails if a non-zero
value was lost, which catches a field that decodes but does not survive the trip.

## Deliberate strictness

`PolicySelector.UnmarshalJSON` rejects an unknown key in the selector object
instead of ignoring it. A selector dimension this build does not know about would
otherwise yield a confidently wrong protection verdict — the worst failure mode
for a discovery tool. Failing loudly is the intended behaviour; revisit only with
a plan for how consumers surface "scope unknown".

## Added by the Go collector

`unpopulatedSections` (`Report.UnpopulatedSections`, with `Report.NotCollected`)
is **not** a KDL.sh field. It was added when `kdl scan` landed as a partial
collector, and it is the only field in this schema that no shell report carries.

It exists because "never computed" and "computed and found nothing" are
indistinguishable from a section's own contents, and the difference is not
cosmetic: a report missing the licence block diffs as *"3 licence(s) removed"*
and one missing the DR block as *"disaster recovery disabled"*. Both are among
the most alarming things these tools can say, and both were false.

`omitempty`, so a KDL.sh report is unaffected and keeps being compared in full.
Absent means "the producer filled everything it knows about", which is the right
default: skipping every empty section would hide a real licence removal.

`StatusNotAssessed` in `schema.go` is the opposite case — it *is* KDL's own
vocabulary, hoisted into the schema so a collector can emit it deliberately
rather than leaving a best-practice field empty. An empty field is read by the
renderer as an unrecognised status, which fails the check: that is how a
Go-collected report once showed "2 Critical" for two checks nobody had looked at.
