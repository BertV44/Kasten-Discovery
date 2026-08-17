// Package diff compares two KDL discovery reports and reports what moved,
// replacing kdl-diff.sh.
//
// Beyond replacing the shell tool, this package does double duty during the
// migration: comparing a shell-produced report against a Go-produced one from
// the same cluster is the gate for retiring KDL.sh. That comparison must ignore
// fields which legitimately differ between two runs -- timestamps, durations,
// ages -- and flag everything else, which is why the identity of each compared
// object is pinned in extract.go rather than left to a structural deep-equal.
//
// Two rules run through the whole package:
//
//   - A metric that was never assessed is not a zero. Node consumption behind a
//     denied RBAC read, an RBAC inventory that could not be listed, a section
//     that did not exist in the baseline's KDL version: each is reported as not
//     comparable rather than diffed into a fake regression.
//   - The verdict vocabulary is Kasten's, not ours. The best-practice pass list
//     is copied from the emitter; inventing a value here would silently
//     reclassify a real state as unknown.
package diff

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/BertV44/Kasten-Discovery/internal/schema"
)

// Version of the diff contract. Tracks kdl-diff.sh, whose v1.0 this reproduces.
const Version = "1.0"

// ExitError carries the process exit status out of Run. The status is the
// regression count (capped at 99) so a CI gate can use `kdl diff` directly;
// 100 is reserved for a usage error, matching kdl-diff.sh.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("%d regression(s) detected", e.Code)
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode lets the command layer exit with this status instead of 1.
func (e *ExitError) ExitCode() int { return e.Code }

// Silent reports whether the message was already delivered by the rendered
// output, so the caller should not print it again as "kdl: ...".
func (e *ExitError) Silent() bool { return e.Err == nil }

const usageExit = 100

// Run is the entry point for `kdl diff`.
func Run(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the comparison as JSON instead of text")
	noColour := fs.Bool("no-color", false, "disable ANSI colour (also disabled when stdout is not a terminal)")
	summary := fs.Bool("summary", false, "show only what changed, dropping the narration")
	showVersion := fs.Bool("version", false, "print the diff contract version and exit")
	// kdl-diff.sh accepts -V; a CI script ported across should not fail on it.
	fs.BoolVar(showVersion, "V", false, "alias for -version")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `kdl diff -- compare two KDL discovery reports

Usage:
  kdl diff <baseline.json> <current.json> [flags]

Flags:
  -json       emit the comparison as JSON instead of text
  -summary    show only what changed
  -no-color   disable ANSI colour
  -version    print the diff contract version

Exit codes:
  0        no regression
  1..99    number of regressions detected (capped at 99)
  100      usage error: bad flags, missing or unreadable file, invalid JSON
`)
	}
	// flag stops at the first non-flag argument, but kdl-diff.sh accepts
	// `<baseline> <current> --summary`. Reject that ordering and the Go tool
	// would be a drop-in replacement everywhere except the command line people
	// actually type, so collect positionals and keep parsing past them.
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		// Asking for help is not a usage error. flag reports -h as ErrHelp after
		// printing the usage text, and exiting 100 there would tell a CI gate
		// that a successful `--help` was a malformed invocation.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return &ExitError{Code: usageExit, Err: err}
	}
	if *showVersion {
		fmt.Printf("kdl diff (contract %s)\n", Version)
		return nil
	}

	if len(positional) != 2 {
		fs.Usage()
		return &ExitError{Code: usageExit, Err: fmt.Errorf("diff: expected two report paths, got %d", len(positional))}
	}
	basePath, curPath := positional[0], positional[1]

	// Lenient decoding on purpose: kdl-diff.sh accepts reports from older KDL
	// versions, and a diff that refuses to run is useless precisely when the two
	// snapshots straddle an upgrade. Strict decoding stays available via
	// `kdl validate`.
	base, err := schema.Load(basePath)
	if err != nil {
		return &ExitError{Code: usageExit, Err: fmt.Errorf("baseline: %w", err)}
	}
	cur, err := schema.Load(curPath)
	if err != nil {
		return &ExitError{Code: usageExit, Err: fmt.Errorf("current: %w", err)}
	}

	res := Compare(base, cur, basePath, curPath)

	if *asJSON {
		if err := RenderJSON(os.Stdout, res); err != nil {
			return &ExitError{Code: usageExit, Err: err}
		}
	} else {
		if err := RenderHuman(os.Stdout, res, colourEnabled(*noColour), *summary); err != nil {
			return &ExitError{Code: usageExit, Err: err}
		}
	}

	if res.Summary.ExitCode != 0 {
		return &ExitError{Code: res.Summary.ExitCode}
	}
	return nil
}

// parseInterspersed parses flags that appear before, between or after the
// positional arguments, and returns the positionals in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// colourEnabled mirrors the shell tool: colour only on a terminal, and never
// when the caller asked for it off.
func colourEnabled(disabled bool) bool {
	if disabled {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
