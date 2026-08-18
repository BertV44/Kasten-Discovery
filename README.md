<!-- Kasten Discovery — Go implementation -->
# Kasten Discovery

Read-only discovery and audit tooling for Veeam Kasten K10 on Kubernetes and
OpenShift. Produces a support-grade inventory — health, RBAC, policies, effective
RPO, ransomware readiness score, best-practice compliance — as JSON and as a
single self-contained HTML report.

Written in Go so it ships as **one static binary with no runtime dependencies**:
the tool runs on a customer's bastion host, where installing an interpreter, or
even `jq`, is often not an option.

> | Command | State |
> |---|---|
> | `kdl report` | **Working** — renders all 35 report sections from a discovery JSON |
> | `kdl validate` | **Working** — type-checks a discovery JSON against the schema |
> | `kdl diff` | **Working** — compares two reports; exit code = regression count |
> | `kdl scan` | **Feature-complete, unverified** — computes every report section; has never run against a live cluster |
>
> The shell implementation at
> [BertV44/Kasten-Disco-Lite](https://github.com/BertV44/Kasten-Disco-Lite) is
> still the tool in use with customers. This repository is where the Go rewrite
> happens; the two share the report JSON as their contract.

### What `kdl scan` does not do

There is no section it cannot compute. There is one figure it cannot compute
*unconditionally*: **catalog free space**.

`KDL.sh` gets it by running `df` inside the catalog pod, and a pod exec is a
*create* against `pods/exec` — a verb the read-only Reader does not have and which
`readonly_test.go` fails the build for so much as naming. "KDL never mutates the
cluster" is a promise made to customers and a percentage is not worth weakening it
for. So the figure comes from the kubelet instead, which already measures every
volume it mounts and publishes the numbers on a `GET`:

```
GET /api/v1/nodes/<node>/proxy/stats/summary
```

That needs `get` on `nodes/proxy`, which is **not** a permission K10 itself
requires, so most clusters will not have granted it. When they have not, the
percentages stay `null`, `catalog.freeSpacePercent` is declared uncomputed, and
the PVC and its size are still collected. The refusal costs nothing else: the read
sits outside the collection plan on purpose, so it never sets `rbacLimited` on the
whole report — six reads were once removed from that plan for exactly that
mistake.

Everything else `kdl scan` leaves empty is either genuinely empty or declared,
**per run**, as a read that did not return. That declaration is the mechanism the
whole collector leans on:

- Uncomputed sections are listed in the report's `unpopulatedSections`, `kdl diff`
  skips any section named there, and the HTML renderer replaces it with a note
  rather than rendering its zero values. Without that, a Go-collected report
  diffed against a shell-collected one announced `3 licence(s) removed` and
  `K10 disaster recovery disabled` — the zero value of a licence list is "no
  licences", and nothing in the section itself distinguishes "never collected"
  from "collected and empty". A report that does *not* declare a section keeps
  being compared normally, so a real licence removal is still caught.
- A section whose input RBAC refused is declared for that run. A scan by a service
  account that cannot read BackupActions says so, instead of reporting that no
  namespace in the cluster was ever backed up.
- The 16 best-practice checks emit `NOT_ASSESSED` rather than passing or failing
  when their input was not read, and the ransomware grade — one number, with no
  room in it for "partly unknown" — is withheld entirely when any pillar's input
  is missing.

### What `kdl scan` reads

Read-only, around thirty resource listings, fetched concurrently. Two are worth
calling out because they are the widest asks in the plan:

- **The Helm release object**: one label-selected Secret, from which only the
  user-supplied `config` values are decoded — the rendered manifests in the rest
  of the payload are never looked at. It is the only source for the settings K10
  writes nowhere else (authentication, KMS, audit logging, concurrency limits).
  `-no-helm` drops the read entirely, and the report records that choice in
  `collectionFlags.skipHelm` and `k10Configuration.source`, because a
  configuration section full of defaults looks nothing like one full of readings.
- **The licence secrets**: read namespace-wide, because K10 licence secrets carry
  no distinguishing label and their names vary across installs and renewals. Only
  secrets whose name contains `license` are looked at, and nothing from the
  payload reaches the report except the licence fields the schema models.

One permission is **optional** and worth granting only if you want the figure:
`get` on `nodes/proxy`, for catalog free space. It is a privileged permission — it
reaches the kubelet API generally — so the scan asks for it best-effort and
carries on without it. Nothing else in the report depends on it, and no
best-practice check or ransomware pillar reads it.

**The collector has never been exercised against a live Kasten install.** Its
field paths are derived from `KDL.sh`'s jq expressions rather than from the
Kasten CRD documentation — the shell tool is what runs against real customer
clusters, so its paths are the validated ones — and where `KDL.sh` resolves a
field with a bounded deep scan, so does this. But the first run against a real
9.0 cluster is still the thing that turns this from *reasoned* into *verified*.

## Install

Download a binary from [Releases](https://github.com/BertV44/Kasten-Discovery/releases)
and make it executable:

```bash
chmod +x kdl-linux-amd64 && sudo mv kdl-linux-amd64 /usr/local/bin/kdl
```

Verify the checksum published alongside it:

```bash
sha256sum -c checksums.txt --ignore-missing
```

Or build from source (Go 1.23 or later):

```bash
git clone https://github.com/BertV44/Kasten-Discovery.git
cd Kasten-Discovery && go build -o kdl ./cmd/kdl
```

The collector pulls in `k8s.io/client-go`, so a first build needs the network.
The renderer, the schema and the diff still import nothing outside the standard
library — only `kdl scan` pays for those dependencies.

## Use

```bash
# Collect a report from the current cluster (read-only)
kdl scan -out discovery.json

# Same, without reading the Helm release object
kdl scan -no-helm -out discovery.json

# Render the HTML report from a discovery JSON
kdl report -in discovery.json -out report.html

# Type-check a report and summarise what it contains
kdl validate -in discovery.json

# Compare two snapshots; exit code is the number of regressions
kdl diff baseline.json current.json --summary
```

`report` writes to stdout when `-out` is omitted. `validate` is strict by
default: a key the schema does not model is an error, which is what makes schema
drift visible the first time a newer KDL produces a report.

`diff` is built for quarterly TAM engagements and for CI gates: it exits 0 when
nothing regressed, with the number of regressions (capped at 99) when something
did, and 100 on a usage error. `--json` emits the same comparison structurally;
its `summary` object keeps `kdl-diff.sh`'s field names so existing gates keep
working.

**The exit code is deliberately identical to `kdl-diff.sh`'s**, because a CI
gate cannot be migrated silently. Anything the shell tool does not fail a run on
— catalog free space falling while still comfortable, node count growing, K10
pods restarting, a policy gaining a dead namespace reference — is reported here
too, but as information rather than as a regression. Adding a new gate is a
change to the contract and belongs behind a flag, not in a patch release.

`scan` never writes to the cluster — see below. It refuses to write a report if
every read failed, because a report of all zeros looks exactly like a cluster
with nothing in it.

The HTML is a single self-contained file — CSS and JS are embedded — because the
report gets emailed and opened from a laptop with no network.

## How it is built

```
cmd/kdl/              CLI: one binary, one subcommand per job
internal/schema/      the report JSON, typed — the contract between all parts
  report.go           generated from a real cluster report, then hand-refined
  selector.go         hand-written: polymorphic policy selector + Kasten globs
  nodelimit.go        node limits are a number OR "unlimited"/"none"
  schema_notes.md     what is verified and what is not — read before trusting a type
  genschema.py        the generator that produced report.go
internal/report/      HTML renderer, all 35 sections
  section.go          the three recurring section shapes, modelled once
  sections.go         every section expressed as data
  bestpractices.go    the 16 best-practice checks as a table
  templates/          page.tmpl plus one block per irregular section
  assets/             style.css and app.js, embedded at build time
internal/scan/        cluster collector
  client.go           the read-only Reader: no write verb exists on it, and the
                      kubelet volume-stats GET is the narrowest shape that works
  resources.go        the collection plan, derived from KDL.sh's kubectl calls
  collect.go          parallel fetch; denied / absent / failed kept apart
  unstruct.go         bounded deep scan, the Go twin of KDL.sh's deep_first
  build.go            collected objects -> typed report, plus what was NOT read
  actions.go          the sections that are a reading of the action listings
  runstats.go         policyRunStats: what the policies did, not what they say
  retention.go        the three retention shapes, with their thresholds
  features.go         whether DR, monitoring and multi-cluster actually work
  config.go           K10's own install config: Helm release + k10-config
  exclusions.go       deliberate opt-outs, and the gaps left once subtracted
  vms.go              the three VM selector shapes, resolved against the VMs
  license.go          licence secrets, and the paid-vs-trial entitlement
  storage.go          catalog PVC and the protected footprint
  verdicts.go         the 16 checks and the 8 ransomware pillars
  readonly_test.go    fails the build if any file names a write verb
internal/diff/        report comparison
  compare.go          the 15 comparison sections, as a table
  extract.go          what identity each compared object is keyed by
_legacy/              the v1.0 sketch this rewrite supersedes, kept for reference
```

Two design decisions carry most of the weight.

**The report is data, not code.** Its 35 sections are three recurring shapes — a
card of label/value rows, a grid of figures, a table — so the shapes are modelled
once and each section is a value in a slice. The 16 best-practice checks are
likewise one table with a severity and an extractor per check, not sixteen blocks.
Adding a section or a check is an entry, and it cannot be counted differently from
its neighbours by accident.

**The schema is derived, not transcribed.** `report.go` was generated from a real
anonymised cluster report and then refined by hand, and every key path the shell
collector emits is checked against it mechanically. `internal/schema/schema_notes.md`
records exactly which types are confirmed by a real report and which are inferred —
read it before trusting a field.

## Kasten 9.0

- A policy can carry **two export actions** (additional export). Nothing here ever
  reads "the" export of a policy; the list is always the unit.
- VM selectors come in three mutually exclusive forms: `appNamespace`,
  `virtualMachineRef` (8.5+, values are `namespace/vmName`), and
  `virtualMachineNamespace` (9.0+). On that third form `matchLabels` filters
  **VMs, not namespaces** — conflating the two is the failure this code is
  structured to prevent.
- `hourly` is a valid retention tier and is rendered.
- VBR block-mode export profiles and hardened-repository immutability are surfaced.

## Test fixtures

Discovery reports are derived from customer clusters and this repository is
public, so **no report is committed here**. Drop an anonymised one at
`testdata/report.json` and the fixture-backed tests run against it; without it
they skip, so a fresh clone stays green.

```bash
go test ./...                                    # skips fixture-backed tests
KDL_FIXTURE=/path/to/report.json go test ./...   # runs them against any report
```

Pointing the tests at a report from a **newer** KDL is the drift detector: the
strict decode fails and names the key that is missing from the schema.

## Contributing

```bash
go build ./... && go vet ./... && go test ./...
gofmt -l ./cmd ./internal
```

CI runs exactly that on every push, then cross-compiles the binaries.

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`). Releases are cut by
pushing a tag: `git tag v0.1.0 && git push origin v0.1.0` builds the binaries,
generates checksums and publishes a GitHub Release.

## Support

Bertrand Castagnet — EMEA TAM, Veeam.
Issues and feature requests via GitHub Issues.

The tool is **read-only**: it never mutates the cluster. That is a promise made
to customers, so it is enforced structurally rather than by convention. The
`Reader` interface in `internal/scan/client.go` has no Create, Update, Patch or
Delete; the dynamic client that does is unexported and never handed out; and
`readonly_test.go` fails the build both if that interface grows a write method
and if any file in the package so much as calls one.
