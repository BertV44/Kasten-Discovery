package scan

// Catalog and data usage: how much space K10 and the workloads it protects are
// actually using.
//
// Both are read from PersistentVolumeClaims, which is the widest read in the
// plan by object count. It is here because it feeds two sections and because
// nothing else answers the question a customer asks first about their catalog:
// how big is it, and is it about to fill up.

import (
	"fmt"
	"regexp"
	"strings"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// buildCatalog identifies the catalog PVC, its size, and how full it is.
//
// The fullness is measured by the kubelet, not by running df in the catalog pod.
// KDL.sh does the latter, and this collector cannot: a pod exec is a create
// against pods/exec, a write verb the Reader has none of and which
// readonly_test.go fails the build for so much as naming. The kubelet already
// measures every volume it mounts and publishes the numbers on a GET, so the
// same figure is available without weakening a promise made to customers.
//
// It is still often absent, because reading it needs get on nodes/proxy and that
// is not a permission K10 itself requires. When it is, the percentages stay null,
// the section declares catalog.freeSpacePercent, and the renderer prints "not
// measured" rather than the 0% that would read as a catalog about to fail.
func buildCatalog(res Result, r *kdl.Report) {
	pvc, found := catalogPVC(res)
	if !found {
		r.Catalog = kdl.Catalog{PVCName: naValue, Size: naValue}
		return
	}
	r.Catalog = kdl.Catalog{
		PVCName: name(pvc),
		Size:    pvcSize(pvc),
	}

	stat, measured := res.VolumeStats[namespace(pvc)+"/"+name(pvc)]
	// A driver that does not implement NodeGetVolumeStats reports the volume with
	// no capacity. Dividing by that would be reporting a full disk from an absent
	// measurement, which is the failure this whole section is careful about.
	if !measured || stat.CapacityBytes == 0 {
		return
	}
	used := int(stat.UsedBytes * 100 / stat.CapacityBytes)
	if used > 100 {
		// The kubelet reports usage against the filesystem, which can exceed the
		// requested capacity on some backends. Clamping keeps the progress bar and
		// the free figure consistent rather than emitting a negative percentage.
		used = 100
	}
	free := 100 - used
	r.Catalog.UsedPercent = &used
	r.Catalog.FreeSpacePercent = &free
}

// catalogPVC finds the catalog claim by label, then by name.
//
// The name fallback is not belt-and-braces: the component=catalog label scheme
// varies with the chart version and with how K10 was installed, and a cluster
// where the label does not match is exactly the kind of install where the
// operator most needs the report to work.
func catalogPVC(res Result) (unstructured.Unstructured, bool) {
	var byName unstructured.Unstructured
	foundByName := false
	for _, o := range res.Items("pvcs") {
		if namespace(o) != res.KastenNamespace {
			continue
		}
		if o.GetLabels()["component"] == "catalog" {
			return o, true
		}
		if !foundByName && strings.Contains(strings.ToLower(name(o)), "catalog") {
			byName, foundByName = o, true
		}
	}
	return byName, foundByName
}

// pvcSize prefers the bound capacity over the request: a claim can be bound to a
// volume larger than it asked for, and the bound size is the one that will fill
// up.
func pvcSize(o unstructured.Unstructured) string {
	if v, ok := str(o.Object, "status", "capacity", "storage"); ok && v != "" {
		return v
	}
	if v, ok := str(o.Object, "spec", "resources", "requests", "storage"); ok && v != "" {
		return v
	}
	return naValue
}

// buildDataUsage totals the protected footprint and, when K10's own reporting
// policy has run, the storage the exports actually occupy.
func buildDataUsage(res Result, r *kdl.Report) {
	pvcs := res.Get("pvcs")
	if pvcs.OK() {
		var capacity float64
		for _, o := range pvcs.Items {
			capacity += gibibytes(pvcSize(o))
		}
		r.DataUsage.TotalPVCs = len(pvcs.Items)
		r.DataUsage.TotalCapacityGi = int(capacity)
	}

	if snaps := res.Get("volumeSnapshots"); snaps.OK() {
		var restoreSize float64
		for _, o := range snaps.Items {
			if v, ok := str(o.Object, "status", "restoreSize"); ok {
				restoreSize += gibibytes(v)
			}
		}
		r.DataUsage.SnapshotDataGi = int(restoreSize)
	}

	r.DataUsage.ExportStorage, r.DataUsage.Deduplication = exportStorage(res)
}

// exportStorage reads the object-store totals off the newest K10 report.
//
// These figures exist only when the k10-system-reports-policy has run, so their
// absence is a configuration fact rather than a collection failure -- and the
// display value says which, because "0 B" and "no reporting policy" lead to
// completely different conversations.
func exportStorage(res Result) (kdl.DataUsageExportStorage, kdl.DataUsageDeduplication) {
	reports := res.Get("k10Reports")

	var newest map[string]any
	newestAt := ""
	for _, o := range reports.Items {
		stats := mapAt(o.Object, "results", "storage", "objectStorage")
		if stats == nil {
			continue
		}
		if ts := creationTimestamp(o); ts >= newestAt {
			newest, newestAt = stats, ts
		}
	}

	if newest == nil {
		return kdl.DataUsageExportStorage{
			Display:    naValue + " (enable k10-system-reports-policy)",
			DataSource: "none",
		}, kdl.DataUsageDeduplication{Ratio: naValue, Display: naValue, Source: "none"}
	}

	physical, _ := toNumber(newest["physicalBytes"])
	logical, _ := toNumber(newest["logicalBytes"])

	storage := kdl.DataUsageExportStorage{
		Display:       humanBytes(physical),
		PhysicalBytes: int(physical),
		LogicalBytes:  int(logical),
		DataSource:    "reports",
	}

	// A ratio below 1 is not an error: encryption and compression overhead can
	// make the stored copy larger than the source, and that is worth seeing.
	dedup := kdl.DataUsageDeduplication{Ratio: naValue, Display: naValue, Source: "reports"}
	if physical > 0 && logical > 0 {
		dedup.Ratio = fmt.Sprintf("%.1f", logical/physical)
		dedup.Display = dedup.Ratio + "x"
	}
	return storage, dedup
}

// quantityPattern splits a Kubernetes quantity into its number and its unit.
var quantityPattern = regexp.MustCompile(`^([0-9.]+)([A-Za-z]*)$`)

// gibibyteScale converts each Kubernetes quantity suffix to GiB.
//
// Both families are here because both are in the field, and mixing them up is
// not a rounding error: an earlier shell implementation stripped the suffix and
// summed the numbers, so a PVC sized in bytes came out as ~9.7e11 GiB and every
// Mi- or Ki-sized claim errored out. The empty suffix is raw bytes.
var gibibyteScale = map[string]float64{
	"Ki": 1.0 / 1048576, "Mi": 1.0 / 1024, "Gi": 1, "Ti": 1024, "Pi": 1048576,
	"K": 1e3 / 1073741824, "M": 1e6 / 1073741824, "G": 1e9 / 1073741824,
	"T": 1e12 / 1073741824, "P": 1e15 / 1073741824,
	"": 1.0 / 1073741824,
}

// gibibytes normalises a Kubernetes quantity to GiB, returning 0 for anything it
// cannot parse. A total is a sum, so one unreadable claim must contribute
// nothing rather than poison the figure.
func gibibytes(quantity string) float64 {
	m := quantityPattern.FindStringSubmatch(strings.TrimSpace(quantity))
	if m == nil {
		return 0
	}
	value, ok := toNumber(m[1])
	if !ok {
		return 0
	}
	scale, known := gibibyteScale[m[2]]
	if !known {
		return 0
	}
	return value * scale
}

// humanBytes formats a byte count the way KDL.sh displays it.
func humanBytes(b float64) string {
	switch {
	case b >= 1073741824:
		return fmt.Sprintf("%.1f GiB", b/1073741824)
	case b >= 1048576:
		return fmt.Sprintf("%.1f MiB", b/1048576)
	case b >= 1024:
		return fmt.Sprintf("%.1f KiB", b/1024)
	default:
		return fmt.Sprintf("%d B", int(b))
	}
}
