// Package scan collects a KDL discovery report straight from the Kubernetes
// API server, replacing the oc/kubectl forks and jq invocations of KDL.sh.
//
// Design constraints carried over from the shell implementation -- none of them
// negotiable:
//
//   - Read-only. The collector only ever constructs read clients. This is
//     enforced structurally rather than by convention: Reader (client.go) has no
//     write verb, the dynamic client that does is unexported, and
//     readonly_test.go fails the build both if that interface grows a write
//     method and if any file in the package so much as names one. "KDL never
//     mutates the cluster" is a promise made to customers.
//   - RBAC degradation is a first-class result, not an error. A denied read is
//     distinguishable from an empty one (Collection.Denied, from
//     apierrors.IsForbidden), because a section fed by a denied read is empty,
//     not zero. Denials surface in the report as schema.RBACLimited and in the
//     accessibility flags.
//   - No CLI switch. Talking to the API server directly removes the oc/kubectl
//     selection KDL.sh needs, along with its failure modes.
//   - Parallel fetches with per-resource error capture, so one denied read costs
//     one section rather than the whole scan.
//
// # What this collector does not do yet
//
// It populates the inventory and the two analyses that the typed schema already
// knows how to compute (coverage, policy analysis). The scoring sections --
// ransomware readiness, the 16 best-practice checks, effective RPO -- are not
// computed; UnpopulatedSections lists them, and `kdl scan` prints that list on
// every run. This is deliberate: those sections are verdicts, and a verdict
// computed over a partially collected cluster is worse than an absent one.
//
// # Unvalidated against a live cluster
//
// Every field path here is derived from KDL.sh's jq expressions rather than
// from the Kasten CRD documentation, because the shell tool is what runs
// against real customer clusters. The paths have still never been exercised
// against a live Kasten install from this code. Where KDL.sh resolves a field
// with a bounded deep scan -- it says the nesting "differs between the
// documented schema and what live clusters return" -- this package does the
// same, so a moved field degrades to "not found" rather than to a confident
// wrong answer.
package scan

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Run is the entry point for `kdl scan`.
func Run(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig (default: KUBECONFIG, then ~/.kube/config, then in-cluster)")
	contextName := fs.String("context", "", "kubeconfig context to use (default: current context)")
	kastenNS := fs.String("namespace", "kasten-io", "namespace Kasten K10 is installed in")
	out := fs.String("out", "", "write the report JSON here (default: stdout)")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall time budget for the collection")
	parallelism := fs.Int("parallelism", 8, "how many resources to fetch concurrently")
	qps := fs.Float64("qps", 20, "client-side API request rate limit")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `kdl scan -- collect a discovery report from a cluster (read-only)

Usage:
  kdl scan [flags]

Flags:
  -kubeconfig path   kubeconfig to use (default: KUBECONFIG, ~/.kube/config, in-cluster)
  -context name      kubeconfig context (default: current)
  -namespace name    Kasten install namespace (default: kasten-io)
  -out path          write the report JSON here (default: stdout)
  -timeout duration  overall time budget (default: 2m)
  -parallelism n     concurrent resource fetches (default: 8)
  -qps n             client-side request rate limit (default: 20)

This command never writes to the cluster.
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Each request gets a slice of the overall budget rather than the whole
	// of it, so one unreachable endpoint cannot consume the entire scan.
	perRequest := *timeout / 4
	if perRequest < 5*time.Second {
		perRequest = 5 * time.Second
	}
	reader, err := NewReader(*kubeconfig, *contextName, float32(*qps), perRequest)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res := Collect(ctx, reader, *kastenNS, *parallelism)

	// A report in which every section is zero because the cluster was never
	// reached is worse than no report: it looks like a cluster with nothing in
	// it. Refuse before writing anything.
	if res.TotalFailure() {
		printSummary(os.Stderr, res, ScanVersion)
		return fmt.Errorf("scan: every read failed -- the cluster was not reached; no report written")
	}

	report := Build(res)

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("scan: encoding report: %w", err)
	}
	encoded = append(encoded, '\n')

	if *out == "" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	} else {
		if err := os.WriteFile(*out, encoded, 0o600); err != nil {
			return fmt.Errorf("scan: writing %s: %w", *out, err)
		}
		fmt.Fprintf(os.Stderr, "[OK] report written: %s\n", *out)
	}

	printSummary(os.Stderr, res, report.KDLVersion)
	return nil
}

// printSummary goes to stderr so it never contaminates a report piped to
// stdout. It states what was denied and what was not computed, because a reader
// comparing this against a KDL.sh report needs to tell "nothing found" from
// "never collected".
func printSummary(w *os.File, res Result, version string) {
	fmt.Fprintf(w, "\nkdl scan (%s), Kubernetes %s, namespace %s\n",
		version, orUnknown(res.KubernetesVersion), res.KastenNamespace)

	var denied, absent, failed []string
	for key, c := range res.Collections {
		switch {
		case c.Denied:
			denied = append(denied, key)
		case c.Absent:
			absent = append(absent, key)
		case c.Err != nil:
			failed = append(failed, fmt.Sprintf("%s (%v)", key, c.Err))
		}
	}

	if len(denied) > 0 {
		fmt.Fprintf(w, "\nRBAC denied %d read(s) -- the matching sections are EMPTY, not zero:\n  %s\n",
			len(denied), strings.Join(sorted(denied), "\n  "))
	}
	if len(failed) > 0 {
		fmt.Fprintf(w, "\n%d read(s) failed:\n  %s\n", len(failed), strings.Join(sorted(failed), "\n  "))
	}
	if len(absent) > 0 {
		fmt.Fprintf(w, "\nNot served by this cluster (normal): %s\n", strings.Join(sorted(absent), ", "))
	}

	fmt.Fprintf(w, "\nSections this collector does not compute yet:\n  %s\n",
		strings.Join(UnpopulatedSections(), ", "))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func sorted(v []string) []string {
	out := append([]string(nil), v...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
