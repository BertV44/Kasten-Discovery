package scan

// Which VMs are actually protected, and by what.
//
// This is the section the three Kasten VM selector shapes exist to make hard.
// A policy targets VMs through one of three mutually exclusive keys, and on the
// 9.0 shape (virtualMachineNamespace) matchLabels filters *VMs*, not namespaces.
// Resolving those labels against the namespace inventory instead would credit a
// whole namespace to a policy that protects a handful of VMs inside it -- which
// is the failure this code, and the schema's selector type, are structured to
// prevent.
//
// A VM can also be covered incidentally, by a namespace policy that happens to
// select the namespace it lives in. That counts as protection -- the VM's PVCs do
// get backed up -- but it is reported separately, because the two are not
// operationally equivalent: a namespace policy does not quiesce the guest.

import (
	"sort"
	"strings"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// containsFold is a case-insensitive substring test. Kasten spells these values
// differently across releases and object kinds, so matching exactly would put a
// real answer in the "unknown" bucket.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), needle)
}

// buildVMProtection resolves every policy against every VM.
//
// It runs only when both listings were read. Computing "0 protected VMs" from a
// denied policy read would report every VM on a virtualization cluster as
// unprotected, which is the most alarming way possible to render a permissions
// problem.
func buildVMProtection(res Result, r *kdl.Report) {
	if !res.Get("policies").OK() || !res.Get("virtualMachines").OK() {
		return
	}

	labelsByVM := map[string]map[string]string{}
	for _, o := range res.Items("virtualMachines") {
		labelsByVM[namespace(o)+"/"+name(o)] = o.GetLabels()
	}

	var (
		protected, byVMPolicy, byNSPolicy int
		unprotectedList                   []string
		hasWildcard                       bool
		explicitRefs                      int
	)

	for i := range r.Virtualization.VMs {
		vm := &r.Virtualization.VMs[i]
		key := vm.Namespace + "/" + vm.Name
		labels := labelsByVM[key]

		var coveredBy []string
		vmScoped, nsScoped := false, false
		for _, p := range r.Policies.Items {
			if isSystemPolicy(p.Name) || !hasAction(p.Actions, "backup") {
				continue
			}
			if p.EffectiveScope() == kdl.ScopeVirtualMachine {
				if vmPolicyCovers(p.Selector, vm.Namespace, vm.Name, labels) {
					coveredBy = append(coveredBy, p.Name)
					vmScoped = true
				}
				continue
			}
			if nsPolicyCovers(p.Selector, vm.Namespace) {
				coveredBy = append(coveredBy, p.Name)
				nsScoped = true
			}
		}
		sort.Strings(coveredBy)

		isProtected := len(coveredBy) > 0
		vm.Protected = &isProtected
		vm.ProtectedBy = coveredBy
		// A VM covered both ways is reported as VM-protected: the explicit policy
		// is the one that quiesces the guest, so it is the operative one.
		switch {
		case vmScoped:
			vm.ProtectionSource = "vmPolicy"
		case nsScoped:
			vm.ProtectionSource = "namespacePolicy"
		}

		if isProtected {
			protected++
		} else {
			unprotectedList = append(unprotectedList, key)
		}
		if vmScoped {
			byVMPolicy++
		}
		if nsScoped {
			byNSPolicy++
		}
	}
	sort.Strings(unprotectedList)

	// VM policies, and how they select. The split matters to a reader: an
	// explicit reference names one VM, a namespace-plus-labels selector will pick
	// up VMs created later, and a wildcard reference does both by accident.
	vmPolicies := make([]kdl.VirtualizationVMPoliciesItem, 0)
	byRef, byLabel := 0, 0
	for _, p := range r.Policies.Items {
		if isSystemPolicy(p.Name) || p.EffectiveScope() != kdl.ScopeVirtualMachine {
			continue
		}
		item := kdl.VirtualizationVMPoliciesItem{
			Name:    p.Name,
			Actions: p.Actions,
		}
		if p.Frequency != nil {
			item.Frequency = *p.Frequency
		}
		// The two selector shapes are kept in separate fields rather than one
		// merged list: a "namespace/vmName" reference names one VM, while a
		// namespace pattern plus VM labels also picks up VMs created later, and a
		// merged list makes the two look the same.
		refs := selectorValues(p.Selector, kdl.KeyVirtualMachineRef)
		if len(refs) > 0 {
			item.VMRefs = refs
			item.SelectorKind = "virtualMachineRef"
			byRef++
			explicitRefs += len(refs)
			if anyGlob(refs) {
				hasWildcard = true
			}
		} else {
			item.VMNamespaces = selectorValues(p.Selector, kdl.KeyVirtualMachineNamespace)
			// VM labels, not namespace labels. Naming the field for what it holds
			// is the last line of defence against the conflation this whole file
			// is arranged to prevent.
			item.VMLabels = p.Selector.MatchLabels
			item.SelectorKind = "virtualMachineNamespace"
			byLabel++
		}
		if item.VMRefs == nil {
			item.VMRefs = []string{}
		}
		vmPolicies = append(vmPolicies, item)
	}
	sort.Slice(vmPolicies, func(i, j int) bool { return vmPolicies[i].Name < vmPolicies[j].Name })

	r.Virtualization.VMPolicies = kdl.VirtualizationVMPolicies{
		Count:           len(vmPolicies),
		ByRefSelector:   &byRef,
		ByLabelSelector: &byLabel,
		Items:           vmPolicies,
	}

	unprotected := len(r.Virtualization.VMs) - protected
	if unprotected < 0 {
		unprotected = 0
	}
	r.Virtualization.Protection = kdl.VirtualizationProtection{
		ProtectedVMs:               protected,
		UnprotectedVMs:             unprotected,
		ExplicitVMRefs:             explicitRefs,
		CoveredByVMPolicies:        &byVMPolicy,
		CoveredByNamespacePolicies: byNSPolicy,
		UnprotectedVMList:          unprotectedList,
		HasWildcardPatterns:        hasWildcard,
		Note:                       vmProtectionNote(len(r.Virtualization.VMs), protected, byVMPolicy, byNSPolicy),
	}
}

// vmProtectionNote says how coverage is achieved, because the count alone does
// not distinguish VMs backed up as VMs from VMs backed up as a side effect of
// their namespace being selected.
func vmProtectionNote(total, protected, byVM, byNS int) string {
	switch {
	case total == 0:
		return "no VMs on this cluster"
	case protected == 0:
		return "no VM-specific or namespace coverage detected"
	case byVM > 0 && byNS > 0:
		return "via VM policies and namespace policies"
	case byVM > 0:
		return "via VM-based policies"
	default:
		return "covered by namespace-level policies"
	}
}

// vmPolicyCovers answers for a VM-scoped policy.
//
// The two shapes are not interchangeable. virtualMachineRef matches
// "namespace/vmName" outright. virtualMachineNamespace matches the namespace and
// then filters on VM labels -- and those labels are the VM's own, which is the
// whole reason this function takes them separately rather than reaching for the
// namespace inventory.
func vmPolicyCovers(sel kdl.PolicySelector, ns, vmName string, vmLabels map[string]string) bool {
	if refs := selectorValues(sel, kdl.KeyVirtualMachineRef); len(refs) > 0 {
		if kdl.GlobAny(refs, ns+"/"+vmName) {
			return true
		}
	}
	nsPats := selectorValues(sel, kdl.KeyVirtualMachineNamespace)
	if len(nsPats) == 0 || !kdl.GlobAny(nsPats, ns) {
		return false
	}
	return labelsMatch(sel.MatchLabels, vmLabels)
}

// nsPolicyCovers answers for a namespace-scoped policy, honouring its NotIn
// exceptions: the catch-all-with-exceptions shape would otherwise mark a
// deliberately excluded namespace's VMs as protected.
func nsPolicyCovers(sel kdl.PolicySelector, ns string) bool {
	if kdl.GlobAny(sel.ExcludedNamespacePatterns(), ns) {
		return false
	}
	if sel.All {
		return true
	}
	// An unrecognised selector is "scope unknown", and claiming it covers this
	// VM would over-report protection -- the worse of the two directions for a
	// backup-posture tool.
	if sel.Unrecognized() {
		return false
	}
	return kdl.GlobAny(sel.NamespacePatterns(), ns)
}

// selectorValues returns the In values of one selector key.
func selectorValues(sel kdl.PolicySelector, key string) []string {
	var out []string
	for _, e := range sel.MatchExpressions {
		if e.Key == key && e.Operator == kdl.OperatorIn {
			out = append(out, e.Values...)
		}
	}
	return out
}

// anyGlob reports whether any pattern contains a wildcard. A wildcard VM
// reference selects VMs that do not exist yet, so the report says when one is in
// play rather than presenting the resolved count as the whole story.
func anyGlob(patterns []string) bool {
	for _, p := range patterns {
		for _, c := range p {
			if c == '*' || c == '?' {
				return true
			}
		}
	}
	return false
}

// buildVMRestorePointConsistency counts VM restore points by whether the guest
// was quiesced.
//
// Kasten freezes the guest through the QEMU guest agent and falls back to a
// crash-consistent snapshot when the freeze is unavailable or times out --
// silently. A crash-consistent copy still restores, but the application inside
// the guest may need its own recovery afterwards, which is a thing to know
// before the restore rather than during it.
func buildVMRestorePointConsistency(res Result, r *kdl.Report) {
	c := res.Get("restorePoints")
	if !c.OK() && !c.Absent {
		return
	}
	if len(r.Virtualization.VMs) == 0 && r.Virtualization.TotalVMs == 0 {
		return
	}

	var counts kdl.VMRestorePointConsistency
	for _, o := range c.Items {
		if !isVMRestorePoint(o) {
			continue
		}
		counts.Total++
		switch consistency(o) {
		case "application":
			counts.ApplicationConsistent++
		case "crash":
			counts.CrashConsistent++
		default:
			counts.Unknown++
		}
	}
	r.Virtualization.VMRestorePoints = counts.Total
	r.Virtualization.VMRestorePointConsistency = &counts
}

// isVMRestorePoint reports whether a restore point covers a VM rather than a
// workload. K10 labels the application type.
func isVMRestorePoint(o unstructured.Unstructured) bool {
	if t := o.GetLabels()["k10.kasten.io/appType"]; t != "" {
		return t == "virtualmachine" || t == "VirtualMachine"
	}
	// Older restore points carry the type in the spec instead.
	if t, ok := str(o.Object, "spec", "appType"); ok {
		return t == "virtualmachine" || t == "VirtualMachine"
	}
	return false
}

// consistency reads the snapshot consistency of a VM restore point, returning ""
// when the object does not say. Absent is its own bucket in the counts: a
// restore point whose consistency was never recorded must not be counted as
// application-consistent, which is the reassuring answer.
func consistency(o unstructured.Unstructured) string {
	for _, path := range [][]string{
		{"spec", "consistency"},
		{"status", "consistency"},
		{"spec", "snapshotConsistency"},
	} {
		v, ok := str(o.Object, path...)
		if !ok || v == "" {
			continue
		}
		switch {
		case containsFold(v, "application"), containsFold(v, "quiesce"):
			return "application"
		case containsFold(v, "crash"):
			return "crash"
		}
	}
	if v := o.GetLabels()["k10.kasten.io/consistency"]; v != "" {
		if containsFold(v, "application") {
			return "application"
		}
		if containsFold(v, "crash") {
			return "crash"
		}
	}
	return ""
}
