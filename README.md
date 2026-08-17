<!-- Kasten Discovery — Go implementation -->
# Kasten Discovery

Read-only discovery and audit tooling for Veeam Kasten K10 on Kubernetes and
OpenShift. Produces a support-grade inventory — health, RBAC, policies, effective
RPO, ransomware readiness score, best-practice compliance — as JSON and as a
single self-contained HTML report.

Written in Go so it ships as **one static binary with no runtime dependencies**:
the tool runs on a customer's bastion host, where installing an interpreter, or
even `jq`, is often not an option.

> **Status: the renderer is complete and tested; the collector is not written yet.**
>
> | Command | State |
> |---|---|
> | `kdl report` | **Working** — renders all 35 report sections from a discovery JSON |
> | `kdl validate` | **Working** — type-checks a discovery JSON against the schema |
> | `kdl scan` | Not implemented — collects from a live cluster |
> | `kdl diff` | Not implemented — compares two reports |
>
> Until `scan` lands, the JSON is produced by the shell implementation at
> [BertV44/Kasten-Disco-Lite](https://github.com/BertV44/Kasten-Disco-Lite),
> which is the tool currently in use with customers. This repository is where the
> Go rewrite happens; the two share the report JSON as their contract.

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

Or build from source (Go 1.23 or later, no network needed — there are no
dependencies yet):

```bash
git clone https://github.com/BertV44/Kasten-Discovery.git
cd Kasten-Discovery && go build -o kdl ./cmd/kdl
```

## Use

```bash
# Render the HTML report from a discovery JSON
kdl report -in discovery.json -out report.html

# Type-check a report and summarise what it contains
kdl validate -in discovery.json
```

`report` writes to stdout when `-out` is omitted. `validate` is strict by
default: a key the schema does not model is an error, which is what makes schema
drift visible the first time a newer KDL produces a report.

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
internal/scan/        collector (not implemented)
internal/diff/        report comparison (not implemented)
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
gofmt -l . | grep -v '^_legacy/'
```

CI runs exactly that on every push, then cross-compiles the binaries.

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`). Releases are cut by
pushing a tag: `git tag v0.1.0 && git push origin v0.1.0` builds the binaries,
generates checksums and publishes a GitHub Release.

## Support

Bertrand Castagnet — EMEA TAM, Veeam.
Issues and feature requests via GitHub Issues.

The tool is **read-only**: it never mutates the cluster. That is a promise made to
customers, and the collector will enforce it structurally rather than by
convention when it lands.
