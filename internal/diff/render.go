package diff

import (
	"encoding/json"
	"fmt"
	"io"
)

// tag and colour per finding kind, mirroring kdl-diff.sh's human output so a
// TAM reading both tools sees the same vocabulary.
var kindTag = map[Kind]struct {
	label  string
	colour string
}{
	KindRegression:  {"[REGRESSION]", colRed},
	KindImprovement: {"[IMPROVED]", colGreen},
	KindNeutral:     {"[CHANGE]", colYellow},
	KindInfo:        {"[INFO]", colCyan},
	KindOK:          {"[OK]", colGreen},
}

const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colRed    = "\033[0;31m"
	colGreen  = "\033[0;32m"
	colYellow = "\033[0;33m"
	colCyan   = "\033[0;36m"
	colBlue   = "\033[0;34m"
)

type palette struct{ on bool }

func (p palette) c(colour, s string) string {
	if !p.on {
		return s
	}
	return colour + s + colReset
}

// RenderHuman writes the terminal report. summaryOnly suppresses the "no
// change" narration, leaving only sections that actually moved.
func RenderHuman(w io.Writer, res Result, colour, summaryOnly bool) error {
	p := palette{on: colour}

	fmt.Fprintf(w, "%s\n", p.c(colBold+colBlue, "== Kasten Discovery diff =="))
	fmt.Fprintf(w, "  baseline: %s (KDL %s, Kasten %s)\n",
		res.Baseline.Path, orNA(res.Baseline.KDLVersion), orNA(res.Baseline.KastenVersion))
	fmt.Fprintf(w, "  current : %s (KDL %s, Kasten %s)\n",
		res.Current.Path, orNA(res.Current.KDLVersion), orNA(res.Current.KastenVersion))

	for _, sec := range res.Sections {
		if summaryOnly && !sec.Changed() {
			continue
		}
		if len(sec.Findings) == 0 && summaryOnly {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", p.c(colBold+colBlue, "== "+sec.Name+" =="))
		if len(sec.Findings) == 0 {
			fmt.Fprintf(w, "  %s No change\n", p.c(colGreen, "[OK]"))
			continue
		}
		for _, f := range sec.Findings {
			// A skipped section's only content is the note saying so, so summary
			// mode must keep it: dropping it turns "not compared" into silence,
			// which reads as "no change".
			if summaryOnly && !sec.Skipped && (f.Kind == KindOK || f.Kind == KindInfo) {
				continue
			}
			tag := kindTag[f.Kind]
			fmt.Fprintf(w, "  %s %s\n", p.c(tag.colour, tag.label), f.Message)
		}
	}

	fmt.Fprintf(w, "\n%s\n", p.c(colBold+colBlue, "== Summary =="))
	regTag := p.c(colGreen, "[OK]  ")
	if res.Summary.Regressions > 0 {
		regTag = p.c(colRed, "[FAIL]")
	}
	fmt.Fprintf(w, "  %s      Regressions:  %d\n", regTag, res.Summary.Regressions)
	fmt.Fprintf(w, "  %s      Improvements: %d\n", p.c(colGreen, "[OK]  "), res.Summary.Improvements)
	fmt.Fprintf(w, "  %s      Neutral:      %d\n", p.c(colCyan, "[INFO]"), res.Summary.NeutralChanges)
	fmt.Fprintf(w, "\n  Exit code: %d\n", res.Summary.ExitCode)
	return nil
}

// RenderJSON writes the machine-readable comparison.
//
// The "summary" object keeps kdl-diff.sh's field names (regressions,
// improvements, neutralChanges, exitCode) because that is what CI gates read.
// The per-section shape deliberately differs: the shell emits an ad-hoc object
// per section, whereas this emits one uniform list of typed findings, which is
// what makes the output usable without a per-section parser.
func RenderJSON(w io.Writer, res Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
