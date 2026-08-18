package report

import "strings"

// Polarity is how a raw KDL status value reads on its own -- good, neutral,
// cautionary or bad -- independently of how much the check carrying it matters.
// Severity is the other half of that pair and lives in bestpractices.go.
type Polarity int

const (
	PolarityOK Polarity = iota
	PolarityInfo
	PolarityWarn
	PolarityBad
)

// Class is the CSS class the stylesheet expects for this polarity.
func (p Polarity) Class() string {
	switch p {
	case PolarityOK:
		return "ok"
	case PolarityInfo:
		return "info"
	case PolarityWarn:
		return "warn"
	default:
		return "error"
	}
}

// Badge is a rendered status pill: the CSS class and the text inside it.
type Badge struct {
	Class string
	Text  string
}

// statusMeta describes one raw status value emitted by KDL.
type statusMeta struct {
	polarity Polarity
	// symbol prefixes the humanised value. It is empty for values that already
	// read as a verdict by themselves ("WARN"), which is how KDL.sh renders them.
	symbol string
}

// statusTable maps every status value KDL emits under bestPractices.
//
// A value missing from this table is reported as unknown rather than defaulting
// to OK. An unrecognised status that renders green is precisely the silent-wrong-
// verdict failure this rewrite exists to remove, so the default leans the other
// way and StatusBadge tells the caller.
var statusTable = map[string]statusMeta{
	"CONFIGURED":            {PolarityOK, "✓"},
	"COMPLETE":              {PolarityOK, "✓"},
	"IN_USE":                {PolarityOK, "✓"},
	"ENABLED":               {PolarityOK, "✓"},
	"OK":                    {PolarityOK, "✓"},
	"CONFIGURED_INCOMPLETE": {PolarityWarn, "⚠"},
	"PARTIAL":               {PolarityInfo, "ℹ"},
	"WARN":                  {PolarityInfo, ""},
	"NOT_CONFIGURED":        {PolarityBad, "✗"},
	"NOT_ENABLED":           {PolarityBad, "✗"},
	"GAPS_DETECTED":         {PolarityBad, "✗"},
	// Two more values KDL.sh emits that no available sample carries, found by
	// reading the emitter rather than by the guard firing on a report: NOT_USED
	// on a cluster with no policy presets, and CONFIGURED_NOT_HEALTHY from the DR
	// verdict, which the best-practice check carries verbatim. Both were
	// rendering as "? …" in amber -- so an unhealthy DR, a critical check, was
	// painted as an unrecognised value rather than as the failure it is.
	"NOT_USED":               {PolarityBad, "✗"},
	"CONFIGURED_NOT_HEALTHY": {PolarityBad, "✗"},

	// Licence status values. Found by the unknown-status guard firing on a real
	// report: VALID was rendering as "? VALID" because only bestPractices values
	// were modelled here.
	//
	// UNKNOWN is the third one KDL.sh emits, for a licence whose dateEnd cannot be
	// read (KDL.sh:960), and it was missing -- so such a licence rendered as an
	// amber "? UNKNOWN" and counted toward the unrecognised-status total. Info, not
	// warn: an unreadable expiry date is neither a live licence nor an expired one.
	//
	// EXPIRING used to sit here and was removed: KDL.sh has no expiry-warning
	// threshold at all -- EXPIRED if daysRemaining is negative, VALID otherwise --
	// so it was exactly the invented entry the note below warns about.
	"VALID":   {PolarityOK, "✓"},
	"EXPIRED": {PolarityBad, "✗"},
	"UNKNOWN": {PolarityInfo, "ℹ"},
	// Node-consumption and paid-entitlement status. These are exactly the values
	// KDL.sh emits (`CONSUMPTION_STATUS` / `PAID_STATUS`) -- an earlier revision
	// also carried OVER_LIMIT, AT_LIMIT, WITHIN_PAID and UNKNOWN, which KDL never
	// produces, while missing EXCEEDED, which it does. Inventing status values
	// makes the guard useless: the real one falls through to "unknown" and gets
	// painted amber instead of red.
	"EXCEEDED":        {PolarityBad, "✗"},
	"EXCEEDS_PAID":    {PolarityBad, "✗"},
	"NO_PAID_LICENSE": {PolarityWarn, "⚠"},
	"NOT_ASSESSED":    {PolarityInfo, "ℹ"},
	"N/A":             {PolarityInfo, "ℹ"},
}

// StatusBadge renders a raw KDL status value as a detail pill. known is false
// when the value is absent from statusTable; the badge is then shown verbatim,
// marked with "?", and treated as a failure by the caller.
func StatusBadge(value string) (badge Badge, polarity Polarity, known bool) {
	meta, known := statusTable[value]
	if !known {
		return Badge{Class: PolarityWarn.Class(), Text: "? " + humanise(value)}, PolarityWarn, false
	}
	text := humanise(value)
	if meta.symbol != "" {
		text = meta.symbol + " " + text
	}
	return Badge{Class: meta.polarity.Class(), Text: text}, meta.polarity, true
}

// humanise turns KDL's SCREAMING_SNAKE status values into display text.
func humanise(value string) string {
	return strings.ReplaceAll(value, "_", " ")
}
