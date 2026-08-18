package scan

import (
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Field access for objects whose exact shape is not guaranteed.
//
// KDL.sh resolves several profile fields with a bounded deep scan and says why:
// "the exact nesting differs between the documented schema and what live
// clusters return". That is the same hazard that a typed CRD struct would walk
// straight into -- a field one level deeper than expected decodes as a zero
// value, and a zero value renders as a confident wrong answer.
//
// So: fixed paths where KDL.sh uses a fixed path, deep scan where KDL.sh deep
// scans, and a miss that is always distinguishable from a zero.

// str reads a string at a fixed path. The bool reports whether the field was
// present, which callers must use rather than testing for "" -- an absent
// field and an empty one are different facts.
func str(obj map[string]any, path ...string) (string, bool) {
	v, ok, err := unstructured.NestedString(obj, path...)
	if err != nil || !ok {
		return "", false
	}
	return v, true
}

// strOr reads a string at a fixed path, falling back when absent. Use only
// where the fallback is a real value rather than a stand-in for "unknown".
func strOr(obj map[string]any, fallback string, path ...string) string {
	if v, ok := str(obj, path...); ok && v != "" {
		return v
	}
	return fallback
}

func boolAt(obj map[string]any, path ...string) (bool, bool) {
	v, ok, err := unstructured.NestedBool(obj, path...)
	if err != nil || !ok {
		return false, false
	}
	return v, true
}

func intAt(obj map[string]any, path ...string) (int64, bool) {
	v, ok, err := unstructured.NestedInt64(obj, path...)
	if err != nil || !ok {
		return 0, false
	}
	return v, true
}

func slice(obj map[string]any, path ...string) []any {
	v, ok, err := unstructured.NestedSlice(obj, path...)
	if err != nil || !ok {
		return nil
	}
	return v
}

func mapAt(obj map[string]any, path ...string) map[string]any {
	v, ok, err := unstructured.NestedMap(obj, path...)
	if err != nil || !ok {
		return nil
	}
	return v
}

// maxDeepScanDepth bounds the recursive search. Kasten's location specs nest a
// handful of levels; anything deeper is a different object and matching there
// would be a coincidence, not a read.
const maxDeepScanDepth = 6

// deepFirstString finds the first non-empty string stored under key anywhere in
// the object, breadth-first so the shallowest match wins. It mirrors KDL.sh's
//
//	def deep_first(f): [ .. | objects | (f // empty) | select(. != null and . != "") ] | first
//
// and exists for the same reason: profile location fields sit at a different
// depth depending on the backend and the Kasten version, so a fixed path
// silently misses them on exactly the clusters worth reporting on.
func deepFirstString(obj any, key string) (string, bool) {
	level := []any{obj}
	for depth := 0; depth < maxDeepScanDepth && len(level) > 0; depth++ {
		var next []any
		for _, node := range level {
			m, ok := node.(map[string]any)
			if !ok {
				if arr, isArr := node.([]any); isArr {
					next = append(next, arr...)
				}
				continue
			}
			// Deterministic order: a map with two candidate keys at the same
			// depth must resolve the same way on every run.
			for _, k := range sortedKeys(m) {
				if k != key {
					continue
				}
				if s, isStr := m[k].(string); isStr && s != "" {
					return s, true
				}
			}
			for _, k := range sortedKeys(m) {
				next = append(next, m[k])
			}
		}
		level = next
	}
	return "", false
}

// deepFirstPresent reports whether a key exists anywhere in the object with a
// value that is neither null nor empty, without caring what type it is.
//
// protectionPeriod is why this exists separately from deepFirstNumber: Kasten
// emits it as a number of seconds on some backends and as a duration string
// ("720h", "30d") on others -- KDL.sh parses the "h" suffix, which is direct
// evidence that live clusters return strings. Requiring a number silently
// scored those profiles as mutable, understating the single most important
// signal in the ransomware section.
func deepFirstPresent(obj any, key string) bool {
	level := []any{obj}
	for depth := 0; depth < maxDeepScanDepth && len(level) > 0; depth++ {
		var next []any
		for _, node := range level {
			m, ok := node.(map[string]any)
			if !ok {
				if arr, isArr := node.([]any); isArr {
					next = append(next, arr...)
				}
				continue
			}
			if raw, present := m[key]; present && !emptyValue(raw) {
				return true
			}
			for _, k := range sortedKeys(m) {
				next = append(next, m[k])
			}
		}
		level = next
	}
	return false
}

func emptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	}
	return false
}

// deepAnyTrue reports whether ANY occurrence of any of the keys, anywhere in the
// object, is boolean true.
//
// It is not deepFirstAny with a bool check, and the difference is a real bug that
// shape produced. deepFirstAny returns the SHALLOWEST occurrence, so a profile
// carrying `locationSpec.objectStore.skipSSLVerify: false` alongside
// `locationSpec.vbr.skipSSLVerify: true` resolved to the first one and the profile
// was reported as verifying TLS. That is the same false clean bill of health
// KDL.sh's 2.2.0 fix was about, reintroduced one level down: its own test is
// `[.. | objects | (.skipSSLVerify? // .skipCertVerification? // empty) |
// select(. == true)] | length > 0` -- any occurrence, not the first.
//
// For a flag that disables certificate verification, any occurrence being true is
// the only safe reading: one unverified endpoint on a profile is an unverified
// profile.
func deepAnyTrue(obj any, keys ...string) bool {
	level := []any{obj}
	for depth := 0; depth < maxDeepScanDepth && len(level) > 0; depth++ {
		var next []any
		for _, node := range level {
			m, ok := node.(map[string]any)
			if !ok {
				if arr, isArr := node.([]any); isArr {
					next = append(next, arr...)
				}
				continue
			}
			for _, key := range keys {
				if b, isBool := m[key].(bool); isBool && b {
					return true
				}
			}
			for _, k := range sortedKeys(m) {
				next = append(next, m[k])
			}
		}
		level = next
	}
	return false
}

// deepFirstNumber is deepFirstString for numeric fields such as
// protectionPeriod, which Kasten emits as a number on some backends and as a
// duration string on others.
func deepFirstNumber(obj any, key string) (float64, bool) {
	level := []any{obj}
	for depth := 0; depth < maxDeepScanDepth && len(level) > 0; depth++ {
		var next []any
		for _, node := range level {
			m, ok := node.(map[string]any)
			if !ok {
				if arr, isArr := node.([]any); isArr {
					next = append(next, arr...)
				}
				continue
			}
			if raw, present := m[key]; present {
				if n, converted := toNumber(raw); converted {
					return n, true
				}
			}
			for _, k := range sortedKeys(m) {
				next = append(next, m[k])
			}
		}
		level = next
	}
	return 0, false
}

// protectionDays turns a protectionPeriod into whole days. Kasten writes it as
// seconds on some backends and as a duration on others; KDL.sh parses the "h"
// suffix, so a report saying "immutability enabled, 0 days" is a misleading
// zero reachable only through the duration shapes.
func protectionDays(v any) (int, bool) {
	if n, ok := toNumber(v); ok && n > 0 {
		return int(n / 86400), true
	}
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(s), "P"))
	for suffix, perDay := range map[string]float64{"H": 24, "D": 1} {
		if !strings.HasSuffix(s, suffix) {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64)
		if err != nil || n <= 0 {
			return 0, false
		}
		return int(n / perDay), true
	}
	return 0, false
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// name and namespace read the two metadata fields every object has.
func name(o unstructured.Unstructured) string      { return o.GetName() }
func namespace(o unstructured.Unstructured) string { return o.GetNamespace() }

// stringsFrom pulls a list of strings out of a []any, dropping anything that is
// not a string rather than guessing at a conversion.
func stringsFrom(raw []any) []string {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// deepFirstAny returns the first non-empty value stored under key, whatever its
// type, so a caller can interpret it itself.
func deepFirstAny(obj any, key string) (any, bool) {
	level := []any{obj}
	for depth := 0; depth < maxDeepScanDepth && len(level) > 0; depth++ {
		var next []any
		for _, node := range level {
			m, ok := node.(map[string]any)
			if !ok {
				if arr, isArr := node.([]any); isArr {
					next = append(next, arr...)
				}
				continue
			}
			if raw, present := m[key]; present && !emptyValue(raw) {
				return raw, true
			}
			for _, k := range sortedKeys(m) {
				next = append(next, m[k])
			}
		}
		level = next
	}
	return nil, false
}
