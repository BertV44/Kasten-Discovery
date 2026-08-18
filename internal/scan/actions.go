package scan

// Sections derived from the action, restore-point and profile listings.
//
// Nothing here reads the cluster: every value comes from a collection the plan
// in resources.go already fetches. The reason they were split out of build.go is
// that all of them share one hazard -- an action object does not live in the
// namespace it acted on.

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Thresholds are KDL.sh's STUCK_HOURS_THRESHOLD and STALE_DAYS_THRESHOLD. Both
// are emitted in the report next to the counts they produced, so a reader never
// has to guess which threshold a "stale" or "stuck" verdict was measured
// against -- and `kdl diff` can tell a changed threshold from a changed cluster.
const (
	stuckActionThresholdHours = 24
	staleBackupThresholdDays  = 7
)

// Action states, as K10 spells them in status.state.
const (
	stateComplete = "Complete"
	stateFailed   = "Failed"
	stateRunning  = "Running"
)

// K10 records the subject of an action in labels rather than in the object's
// own namespace. These are the two that matter here.
const (
	appNamespaceLabel = "k10.kasten.io/appNamespace"
	policyNameLabel   = "k10.kasten.io/policyName"
)

// maxActionListItems and maxActionMessage are KDL.sh's caps: five entries per
// list, 180 characters per message. The message cap exists because a Kanister
// failure cause can run to several kilobytes of Go stack.
const (
	maxActionListItems = 5
	maxActionMessage   = 180
)

// actionKinds pairs each action listing with the kind name the report uses. The
// order is the order KDL.sh concatenates them in, which only shows through on a
// timestamp tie.
var actionKinds = []struct{ key, kind string }{
	{"backupActions", "BackupAction"},
	{"exportActions", "ExportAction"},
	{"restoreActions", "RestoreAction"},
}

// actionKeys names the three collections, for the input requirements below.
var actionKeys = []string{"backupActions", "exportActions", "restoreActions"}

// eachAction visits every collected action, tagged with its kind.
func eachAction(res Result, visit func(kind string, o unstructured.Unstructured)) {
	for _, ak := range actionKinds {
		for _, o := range res.Items(ak.key) {
			visit(ak.kind, o)
		}
	}
}

// actionSubjectNamespace resolves the application namespace an action acted on,
// or "" when the object does not say.
//
// It deliberately does not fall back to metadata.namespace. Every K10 action
// object lives in the K10 install namespace, so that fallback attributes the
// entire cluster's backup history to kasten-io -- which is precisely the bug
// KDL.sh carried until it started keying these by the appNamespace label, and
// while it lasted every namespace in every report read as never backed up.
func actionSubjectNamespace(o unstructured.Unstructured, kind string) string {
	if v := o.GetLabels()[appNamespaceLabel]; v != "" {
		return v
	}
	// A RestoreAction names its target in the spec: it is not run by a policy,
	// so nothing labels it.
	if kind == "RestoreAction" {
		if v, ok := str(o.Object, "spec", "subject", "namespace"); ok && v != "" {
			return v
		}
	}
	return ""
}

// actionDisplayNamespace is actionSubjectNamespace plus the fallbacks KDL.sh
// applies in the failed and stuck lists. There, naming the install namespace is
// better than naming nothing, because the item is one row a human will go and
// look at rather than a figure something is counted from.
func actionDisplayNamespace(o unstructured.Unstructured, kind string) string {
	if ns := actionSubjectNamespace(o, kind); ns != "" {
		return ns
	}
	if ns := o.GetNamespace(); ns != "" {
		return ns
	}
	return "N/A"
}

// actionPolicy names the policy that ran an action. Restores carry no policy
// label -- a restore is triggered, not scheduled -- so the field stays empty
// rather than becoming "unknown", which would read as a lost reference.
func actionPolicy(o unstructured.Unstructured) string {
	return o.GetLabels()[policyNameLabel]
}

func creationTimestamp(o unstructured.Unstructured) string {
	ts, _ := str(o.Object, "metadata", "creationTimestamp")
	return ts
}

// buildFailedActions collects the five most recent failed actions across all
// three kinds.
//
// Count is the length of that list, capped at five, and not the number of
// failures in the cluster. That is KDL.sh's field and it is kept identical:
// health.backups already carries the real totals, and a `kdl diff` between a
// Go-collected and a shell-collected report has to compare like with like.
func buildFailedActions(res Result, r *kdl.Report) {
	var items []kdl.FailedActionsTop5Item
	eachAction(res, func(kind string, o unstructured.Unstructured) {
		if state, _ := str(o.Object, "status", "state"); state != stateFailed {
			return
		}
		items = append(items, kdl.FailedActionsTop5Item{
			Kind:      kind,
			Name:      name(o),
			Namespace: actionDisplayNamespace(o, kind),
			Policy:    actionPolicy(o),
			Timestamp: creationTimestamp(o),
			Message:   truncateMessage(deepestMessage(mapAt(o.Object, "status", "error"))),
		})
	})

	// Newest first. Name breaks the tie so two runs over one cluster produce
	// byte-identical reports; jq's ordering on equal timestamps is an accident
	// of group_by and would show up in `kdl diff` as movement.
	sort.Slice(items, func(i, j int) bool {
		if items[i].Timestamp != items[j].Timestamp {
			return items[i].Timestamp > items[j].Timestamp
		}
		return items[i].Name < items[j].Name
	})
	if len(items) > maxActionListItems {
		items = items[:maxActionListItems]
	}
	r.FailedActionsTop5 = kdl.FailedActionsTop5{Count: len(items), Items: items}
}

// buildStuckActions lists actions still Running past the threshold. An action
// Running for a day is almost always a Kanister job or an exec that never
// returned, and it is invisible in the success/failure counts: it has not
// failed, so nothing else in the report mentions it.
func buildStuckActions(res Result, r *kdl.Report, now time.Time) {
	// Emitted even when the list is not computed: the threshold is a property of
	// this build, not a finding about the cluster.
	r.StuckActions.ThresholdHours = stuckActionThresholdHours

	var items []kdl.StuckActionItem
	eachAction(res, func(kind string, o unstructured.Unstructured) {
		if state, _ := str(o.Object, "status", "state"); state != stateRunning {
			return
		}
		ts := creationTimestamp(o)
		age, ok := ageHours(ts, now)
		if !ok || age < stuckActionThresholdHours {
			return
		}
		items = append(items, kdl.StuckActionItem{
			Kind:      kind,
			Name:      name(o),
			Namespace: actionDisplayNamespace(o, kind),
			Policy:    actionPolicy(o),
			Timestamp: ts,
			AgeHours:  age,
		})
	})

	sort.Slice(items, func(i, j int) bool {
		if items[i].AgeHours != items[j].AgeHours {
			return items[i].AgeHours > items[j].AgeHours
		}
		return items[i].Name < items[j].Name
	})
	if len(items) > maxActionListItems {
		items = items[:maxActionListItems]
	}
	r.StuckActions.Count = len(items)
	r.StuckActions.Items = items
}

// buildNamespaceProtection answers, per application namespace, when it was last
// backed up -- which is a different question from whether a policy selects it.
// Coverage answers the second; a namespace can be selected by a policy that has
// never successfully run, and only this section shows that.
//
// The namespace list is coverage's application namespaces. KDL.sh unions in its
// protected-namespace list and intersects with the namespace listing, because
// its protected list is built from policy targets and can name namespaces that
// do not exist. Here the protected set is derived from the namespace inventory
// itself, so it is already a subset of the application namespaces and the union
// would be a no-op.
func buildNamespaceProtection(res Result, r *kdl.Report, now time.Time) {
	r.NamespaceProtectionStatus.ThresholdDays = staleBackupThresholdDays
	r.NamespaceProtectionStatus.Note = "Stale = last successful backup older than thresholdDays"

	lastBackup := lastCompleteByNamespace(res, "backupActions", "BackupAction")
	lastExport := lastCompleteByNamespace(res, "exportActions", "ExportAction")
	lastRestore := lastCompleteByNamespace(res, "restoreActions", "RestoreAction")

	items := make([]kdl.NamespaceProtectionStatusItem, 0)
	stale, never := 0, 0
	for _, ns := range r.Coverage.NamespacesInventory.Items {
		if ns.IsSystem {
			continue
		}
		item := kdl.NamespaceProtectionStatusItem{
			Namespace:   ns.Name,
			LastBackup:  optional(lastBackup[ns.Name]),
			LastExport:  optional(lastExport[ns.Name]),
			LastRestore: optional(lastRestore[ns.Name]),
		}
		if item.LastBackup == nil {
			item.NeverBackedUp = true
			never++
		} else if days, ok := ageDays(*item.LastBackup, now); ok {
			item.BackupAgeDays = &days
			item.Stale = days > staleBackupThresholdDays
			if item.Stale {
				stale++
			}
		}
		items = append(items, item)
	}

	r.NamespaceProtectionStatus.Total = len(items)
	r.NamespaceProtectionStatus.Stale = stale
	r.NamespaceProtectionStatus.NeverBackedUp = never
	r.NamespaceProtectionStatus.Items = items
}

// lastCompleteByNamespace maps an application namespace to the newest
// creationTimestamp among its completed actions of one kind.
//
// Actions whose subject namespace cannot be resolved are dropped rather than
// bucketed somewhere: attributing them to the install namespace would invent a
// backup history for kasten-io, and attributing them to "unknown" would put a
// bucket in the list that is not a namespace.
func lastCompleteByNamespace(res Result, key, kind string) map[string]string {
	out := map[string]string{}
	for _, o := range res.Items(key) {
		if state, _ := str(o.Object, "status", "state"); state != stateComplete {
			continue
		}
		ns := actionSubjectNamespace(o, kind)
		if ns == "" {
			continue
		}
		// RFC 3339 in UTC, which Kubernetes always emits, orders
		// lexicographically. KDL.sh sorts these as strings for the same reason.
		if ts := creationTimestamp(o); ts > out[ns] {
			out[ns] = ts
		}
	}
	return out
}

// buildRestorePointsByNamespace ranks namespaces by how many restore points
// they hold. It is the cheapest signal of a policy whose retention never prunes.
func buildRestorePointsByNamespace(res Result, r *kdl.Report) {
	counts := map[string]int{}
	for _, o := range res.Items("restorePoints") {
		ns := actionSubjectNamespace(o, "RestorePoint")
		if ns == "" {
			ns = o.GetNamespace()
		}
		if ns == "" {
			ns = "unknown"
		}
		counts[ns]++
	}

	top := make([]kdl.RestorePointsByNamespaceTop5Item, 0, len(counts))
	for ns, n := range counts {
		top = append(top, kdl.RestorePointsByNamespaceTop5Item{Namespace: ns, Count: n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Namespace < top[j].Namespace
	})
	if len(top) > maxActionListItems {
		top = top[:maxActionListItems]
	}
	r.RestorePointsByNamespace = kdl.RestorePointsByNamespace{Top5: top}
}

// buildOrphanedRestorePoints finds restore points whose policy no longer
// exists. They still consume catalog space and still appear in the UI, and
// nothing deletes them: the policy that would have applied retention is gone.
func buildOrphanedRestorePoints(res Result, r *kdl.Report) {
	live := map[string]bool{}
	for _, p := range r.Policies.Items {
		live[p.Name] = true
	}

	var items []kdl.OrphanedRestorePointItem
	seen := map[string]bool{}
	for _, o := range res.Items("restorePoints") {
		action, ok := str(o.Object, "spec", "source", "actionName")
		if !ok || action == "" {
			continue
		}
		policy, parsed := policyFromActionName(action)
		if !parsed || live[policy] {
			continue
		}
		if seen[name(o)] {
			continue
		}
		seen[name(o)] = true
		ns := actionSubjectNamespace(o, "RestorePoint")
		if ns == "" {
			ns = o.GetNamespace()
		}
		if ns == "" {
			ns = "unknown"
		}
		items = append(items, kdl.OrphanedRestorePointItem{
			Name:      name(o),
			Namespace: ns,
			Created:   creationTimestamp(o),
			Actions:   []string{action},
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	r.OrphanedRestorePoints = kdl.OrphanedRestorePoints{Count: len(items), Items: items}
}

// policyFromActionName recovers the policy name from the action that created a
// restore point. K10 names an action "<policy>-<three generated segments>", so
// the policy is the name with its last three dash-separated segments removed.
// It is a parse, not a lookup: a restore point holds no policy reference.
//
// A name too short to carry three trailing segments is reported unparsable and
// its restore point is left alone. KDL.sh joins the empty remainder instead,
// which never matches a policy and so calls every such restore point orphaned.
// A name we cannot read is not evidence that a policy was deleted, and this
// section's whole output is an accusation about missing policies.
func policyFromActionName(action string) (string, bool) {
	const generatedSegments = 3
	parts := strings.Split(action, "-")
	if len(parts) <= generatedSegments {
		return "", false
	}
	return strings.Join(parts[:len(parts)-generatedSegments], "-"), true
}

// buildProfileValidation surfaces per-profile validation state. A profile in
// Failed state breaks every export that targets it while the policies
// themselves keep reporting as configured, so this is the section that explains
// an export backlog nothing else accounts for.
func buildProfileValidation(res Result, r *kdl.Report) {
	items := make([]kdl.ProfileValidationItem, 0)
	failed := 0
	for _, o := range res.Items("profiles") {
		item := kdl.ProfileValidationItem{Name: name(o), State: "Unknown"}
		if v, ok := str(o.Object, "status", "validation"); ok && v != "" {
			item.State = v
		} else if v, ok := str(o.Object, "status", "state"); ok && v != "" {
			item.State = v
		}
		if msg := profileError(mapAt(o.Object, "status", "error")); msg != "" {
			item.Error = &msg
		}
		// Kasten spells this state both ways across releases; counting only one
		// of them silently halves the figure the report leads with.
		if item.State == stateFailed || item.State == "Failing" {
			failed++
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	r.ProfileValidation = kdl.ProfileValidation{FailedCount: failed, Items: items}
}

// profileError renders a profile's error as the string the schema types it as.
// KDL.sh emits `.message // .cause`, and cause is sometimes an object -- so on
// that path it emits an object into a field every consumer reads as a string.
// Taking the innermost message out of it keeps the field a string without
// discarding the reason.
func profileError(errObj map[string]any) string {
	if errObj == nil {
		return ""
	}
	if msg, ok := str(errObj, "message"); ok && msg != "" {
		return msg
	}
	switch cause := errObj["cause"].(type) {
	case string:
		return cause
	case map[string]any:
		return deepestMessage(cause)
	}
	return ""
}

// deepestMessage unwraps a K10 action error to its innermost message.
//
// status.error is a chain: every level carries a message and a cause, and the
// cause is sometimes a nested object and sometimes a whole JSON document
// encoded as a string. Only the innermost message names the actual failure --
// the outer levels say "backup failed", which the reader already knows from
// being in the failed-actions list.
//
// The depth bound is KDL.sh's five and is not decoration: a cause that decodes
// to something containing itself would otherwise not terminate.
func deepestMessage(errObj map[string]any) string {
	return deepestMessageAt(errObj, 5)
}

func deepestMessageAt(m map[string]any, depth int) string {
	if m == nil || depth <= 0 {
		return ""
	}
	msg, _ := str(m, "message")
	var next map[string]any
	switch cause := m["cause"].(type) {
	case string:
		if cause == "" {
			return msg
		}
		if err := json.Unmarshal([]byte(cause), &next); err != nil {
			// A cause that is prose rather than JSON is still the better
			// message when the level above had none.
			if msg == "" {
				return cause
			}
			return msg
		}
	case map[string]any:
		next = cause
	default:
		return msg
	}
	if deeper := deepestMessageAt(next, depth-1); deeper != "" {
		return deeper
	}
	return msg
}

// truncateMessage caps a message at KDL.sh's 180 characters, counting runes
// rather than bytes: cutting a UTF-8 sequence in half would put a replacement
// character in the report.
func truncateMessage(s string) string {
	runes := []rune(s)
	if len(runes) <= maxActionMessage {
		return s
	}
	return string(runes[:maxActionMessage]) + "..."
}

// ageHours and ageDays measure elapsed time from an RFC 3339 timestamp,
// reporting failure rather than zero when the field cannot be parsed: an age of
// zero means "just now", which is the opposite of "we could not tell".
func ageHours(ts string, now time.Time) (int, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return int(now.Sub(t).Hours()), true
}

func ageDays(ts string, now time.Time) (int, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return int(now.Sub(t).Hours() / 24), true
}

// optional turns a lookup miss into JSON null. These fields are typed as
// pointers because "never backed up" and "backed up at the zero time" are
// different facts and the renderer prints them differently.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
