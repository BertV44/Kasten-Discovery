package scan

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Collection is the outcome of one resource fetch.
//
// The three failure modes are kept apart on purpose, because they mean
// different things to a reader of the report:
//
//	Denied  -- RBAC refused the read. The section is EMPTY, not zero. Reporting
//	           "0 policies" here would be a lie, and it is the exact lie KDL.sh
//	           goes out of its way to avoid.
//	Absent  -- the cluster does not serve this resource at all (no KubeVirt, no
//	           OpenShift routes). Nothing to report, and nothing is wrong.
//	Err     -- anything else: a real failure worth surfacing.
//
// A caller that treats all three as "empty list" turns a permissions problem
// into a clean bill of health.
type Collection struct {
	Key    string
	Items  []unstructured.Unstructured
	Denied bool
	Absent bool
	Err    error
}

// OK reports whether the read actually happened and can be counted.
func (c Collection) OK() bool { return !c.Denied && !c.Absent && c.Err == nil }

// Result holds every collection, keyed by target key.
type Result struct {
	Collections map[string]Collection
	// KubernetesVersion is empty when discovery itself was refused.
	KubernetesVersion string
	// KastenNamespace is the namespace the Kasten-scoped reads used.
	KastenNamespace string
	// CollectedAt is when the collection ran. Every age in the report -- a stuck
	// action, a stale namespace -- is measured from it rather than from
	// time.Now() at render time, so the same Result always builds the same
	// report and a test can state what "now" is.
	CollectedAt time.Time
}

// Now is the instant ages are measured from, falling back to the current time
// for a Result assembled without one.
func (r Result) Now() time.Time {
	if r.CollectedAt.IsZero() {
		return time.Now()
	}
	return r.CollectedAt
}

// Denials lists the keys whose read was refused, sorted for a stable report.
func (r Result) Denials() []string {
	var out []string
	for k, c := range r.Collections {
		if c.Denied {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Items returns the objects of a collection, or nil. Callers that need to tell
// "denied" from "empty" must consult the Collection itself -- this accessor
// deliberately does not let them pretend the difference does not exist, which
// is why nothing here returns a bool.
func (r Result) Items(key string) []unstructured.Unstructured {
	return r.Collections[key].Items
}

// Get returns the whole collection so a caller can branch on Denied/Absent.
func (r Result) Get(key string) Collection { return r.Collections[key] }

// Succeeded counts the reads that actually returned data.
func (r Result) Succeeded() int {
	n := 0
	for _, c := range r.Collections {
		if c.OK() {
			n++
		}
	}
	return n
}

// TotalFailure reports that not one read succeeded, which means the cluster was
// never reached. A report built from that is entirely zeros, and writing it as
// though it described a cluster is the misleading zero at its largest scale --
// so `kdl scan` refuses rather than emitting it.
func (r Result) TotalFailure() bool {
	return len(r.Collections) > 0 && r.Succeeded() == 0
}

// Collect fetches every target concurrently, capturing each failure against its
// own resource instead of failing the whole scan. One denied read must not cost
// the other thirty-odd sections.
func Collect(ctx context.Context, r Reader, kastenNS string, parallelism int) Result {
	all := targets(kastenNS)
	res := Result{
		Collections:     make(map[string]Collection, len(all)),
		KastenNamespace: kastenNS,
		CollectedAt:     time.Now(),
	}

	if v, err := r.ServerVersion(); err == nil {
		res.KubernetesVersion = v
	}

	if parallelism < 1 {
		parallelism = 1
	}
	sem := make(chan struct{}, parallelism)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	for _, t := range all {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := fetch(ctx, r, t, kastenNS)

			mu.Lock()
			res.Collections[t.key] = c
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return res
}

func fetch(ctx context.Context, r Reader, t target, kastenNS string) Collection {
	c := Collection{Key: t.key}

	// Asking discovery first turns "this cluster has no KubeVirt" into a clean
	// Absent rather than into a NotFound error indistinguishable from a typo in
	// the resource name.
	//
	// A discovery failure must NOT fall through to Absent: on an unreachable
	// cluster that would report every optional resource as "not served by this
	// cluster (normal)", dressing a total outage up as a normal configuration.
	if t.optional {
		has, err := r.HasResource(t.gvr)
		switch {
		case err != nil:
			c.Err = fmt.Errorf("discovery failed, cannot tell absent from unreachable: %w", err)
			return c
		case !has:
			c.Absent = true
			return c
		}
	}

	ns := ""
	if t.namespaced {
		ns = kastenNS
	}

	list, err := r.List(ctx, t.gvr, ns)
	switch {
	case err == nil:
		c.Items = list.Items
	case Denied(err):
		c.Denied = true
		c.Err = err
	case Absent(err):
		c.Absent = true
	default:
		c.Err = err
	}
	return c
}
