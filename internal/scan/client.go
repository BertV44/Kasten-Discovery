package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Reader is the only door this package has onto a cluster.
//
// "KDL never mutates the cluster" is a promise made to customers, so it is
// enforced by the type system rather than by review: the method set below has
// no Create, Update, Patch, Delete or DeleteCollection, and the dynamic client
// that does have them is unexported and never handed out. Widening this
// interface is the one change in this package that must never be made
// casually -- readonly_test.go fails the build if it grows a write verb, and
// again if any file in the package names one.
type Reader interface {
	// List returns every object of a resource, cluster-wide when namespace is "".
	//
	// labelSelector narrows the read server-side. It exists for one read that
	// must not be done broadly: the Helm release object is found by label, and
	// listing the namespace's Secrets to search for it client-side would pull
	// every secret in the Kasten namespace across the wire to use one.
	List(ctx context.Context, gvr k8sschema.GroupVersionResource, namespace, labelSelector string) (*unstructured.UnstructuredList, error)
	// Get returns one named object.
	Get(ctx context.Context, gvr k8sschema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error)
	// NodeVolumeStats reports what the kubelet on one node measures for the
	// volumes mounted there.
	//
	// It exists because the alternative does not: the only other way to learn how
	// full a PVC is, is to run df inside a pod, and a pod exec is a create against
	// pods/exec. This is a plain GET on the node's proxy subresource, so the
	// read-only guarantee holds -- and the path is built from the node name inside
	// the implementation rather than taken from the caller, so this does not
	// become a general "fetch any URL" hole in an interface whose whole purpose is
	// to be narrow.
	NodeVolumeStats(ctx context.Context, nodeName string) ([]VolumeStat, error)
	// ServerVersion reports the Kubernetes version, for the report header.
	ServerVersion() (string, error)
	// HasResource reports whether the cluster serves a resource at all, which
	// distinguishes "this cluster has no VMs" from "this cluster has no KubeVirt".
	HasResource(gvr k8sschema.GroupVersionResource) (bool, error)
}

// VolumeStat is one volume's usage as the kubelet measures it.
//
// Bytes rather than a percentage: the percentage is a presentation choice, and
// the report states both the size and the fraction used.
type VolumeStat struct {
	PVCNamespace   string
	PVCName        string
	CapacityBytes  uint64
	UsedBytes      uint64
	AvailableBytes uint64
}

// clusterReader is the live implementation. Its fields are unexported so no
// caller can reach the write verbs of the underlying dynamic client.
type clusterReader struct {
	dyn   dynamic.Interface
	disco discovery.DiscoveryInterface
	// rest reaches the node proxy subresource, which the dynamic client cannot
	// address. Unexported for the same reason as dyn: the type it holds can write,
	// and nothing outside this file may reach it.
	rest rest.Interface

	// Discovery is resolved once and shared by every concurrent fetch, so it
	// needs a Once rather than a plain lazy assignment: Collect runs the
	// targets in parallel and would otherwise race on the map.
	discoOnce sync.Once
	resources map[k8sschema.GroupVersionResource]bool
	discoErr  error
}

// NewReader builds a read-only cluster reader from a kubeconfig, or from the
// in-cluster service account when kubeconfigPath is empty and no kubeconfig is
// discoverable.
//
// timeout bounds every individual request. It is not redundant with the
// context passed to Collect: the discovery client's calls take no context at
// all, so without a deadline on the REST config a scan against an unreachable
// cluster hangs well past its stated time budget.
func NewReader(kubeconfigPath, contextName string, qps float32, timeout time.Duration) (Reader, error) {
	cfg, err := restConfig(kubeconfigPath, contextName)
	if err != nil {
		return nil, err
	}
	// A discovery tool that saturates a customer's API server is a discovery
	// tool nobody runs twice.
	cfg.QPS = qps
	cfg.Burst = int(qps * 2)
	cfg.Timeout = timeout
	cfg.UserAgent = "kdl-scan (read-only discovery)"

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	disco, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building discovery client: %w", err)
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building core client: %w", err)
	}
	return &clusterReader{dyn: dyn, disco: disco, rest: core.CoreV1().RESTClient()}, nil
}

func restConfig(kubeconfigPath, contextName string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err == nil {
		return cfg, nil
	}
	// Falling back to the in-cluster config lets `kdl scan` run as a Job in the
	// cluster it is describing, which is how a customer with no bastion runs it.
	if inCluster, inErr := rest.InClusterConfig(); inErr == nil {
		return inCluster, nil
	}
	return nil, fmt.Errorf("no usable kubeconfig and not running in-cluster: %w", err)
}

func (c *clusterReader) List(ctx context.Context, gvr k8sschema.GroupVersionResource, namespace, labelSelector string) (*unstructured.UnstructuredList, error) {
	opts := metav1.ListOptions{LabelSelector: labelSelector}
	ri := c.dyn.Resource(gvr)
	if namespace != "" {
		return ri.Namespace(namespace).List(ctx, opts)
	}
	return ri.List(ctx, opts)
}

func (c *clusterReader) Get(ctx context.Context, gvr k8sschema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	ri := c.dyn.Resource(gvr)
	if namespace != "" {
		return ri.Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	return ri.Get(ctx, name, metav1.GetOptions{})
}

// NodeVolumeStats reads the kubelet's own volume measurements off one node.
//
// The endpoint is the kubelet's Summary API, reached through the API server:
// GET /api/v1/nodes/<node>/proxy/stats/summary. Every mounted volume that its
// CSI driver reports stats for appears there with its PVC reference, so the
// figure a df would produce is available without executing anything.
//
// A driver that does not implement NodeGetVolumeStats simply omits the numbers,
// which surfaces here as a zero capacity and is discarded by the caller rather
// than reported as a full disk.
func (c *clusterReader) NodeVolumeStats(ctx context.Context, nodeName string) ([]VolumeStat, error) {
	raw, err := c.rest.Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy").
		Suffix("stats", "summary").
		DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	// Only the fields needed are modelled. The Summary API carries per-pod CPU,
	// memory and network counters as well, and decoding those would be reading a
	// great deal of a customer's telemetry to reach two numbers.
	var summary struct {
		Pods []struct {
			Volume []struct {
				CapacityBytes  uint64 `json:"capacityBytes"`
				UsedBytes      uint64 `json:"usedBytes"`
				AvailableBytes uint64 `json:"availableBytes"`
				PVCRef         *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pvcRef"`
			} `json:"volume"`
		} `json:"pods"`
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		return nil, fmt.Errorf("decoding kubelet stats for node %s: %w", nodeName, err)
	}

	var out []VolumeStat
	for _, pod := range summary.Pods {
		for _, v := range pod.Volume {
			// An ephemeral volume has no PVC reference and cannot be matched to
			// anything in the report.
			if v.PVCRef == nil || v.PVCRef.Name == "" {
				continue
			}
			out = append(out, VolumeStat{
				PVCNamespace:   v.PVCRef.Namespace,
				PVCName:        v.PVCRef.Name,
				CapacityBytes:  v.CapacityBytes,
				UsedBytes:      v.UsedBytes,
				AvailableBytes: v.AvailableBytes,
			})
		}
	}
	return out, nil
}

func (c *clusterReader) ServerVersion() (string, error) {
	v, err := c.disco.ServerVersion()
	if err != nil {
		return "", err
	}
	return v.GitVersion, nil
}

// HasResource answers from the server's advertised resource lists. A cluster
// that does not serve kubevirt.io has no VMs to report, which is a different
// statement from "the VM listing came back empty" and must stay distinguishable.
//
// A discovery failure is returned as an error and never as "not served". The
// difference matters more than it looks: an unreachable cluster answers every
// optional resource with false, and reporting that as "not served by this
// cluster (normal)" tells the reader a total outage is a normal configuration.
func (c *clusterReader) HasResource(gvr k8sschema.GroupVersionResource) (bool, error) {
	c.discoOnce.Do(func() { c.resources, c.discoErr = c.discover() })
	if c.discoErr != nil {
		return false, c.discoErr
	}
	return c.resources[gvr], nil
}

func (c *clusterReader) discover() (map[k8sschema.GroupVersionResource]bool, error) {
	_, lists, err := c.disco.ServerGroupsAndResources()
	// A partial discovery error is normal on clusters with a broken aggregated
	// API: the groups that did answer are still usable. Anything else means we
	// did not reach the API server, and nothing below can be trusted.
	if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
		return nil, err
	}
	out := make(map[k8sschema.GroupVersionResource]bool, len(lists)*8)
	for _, l := range lists {
		gv, parseErr := k8sschema.ParseGroupVersion(l.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, r := range l.APIResources {
			out[gv.WithResource(r.Name)] = true
		}
	}
	return out, nil
}

// Denied reports whether an error is the API server refusing the read rather
// than the read finding nothing. This distinction is the whole point of the
// accessibility flags: a section fed by a denied read is empty, not zero.
func Denied(err error) bool {
	return errors.IsForbidden(err) || errors.IsUnauthorized(err)
}

// Absent reports whether the resource type itself is not served, which is how a
// cluster without KubeVirt or without OpenShift routes answers.
func Absent(err error) bool {
	return errors.IsNotFound(err) || meta(err)
}

func meta(err error) bool {
	return errors.IsResourceExpired(err) || discovery.IsGroupDiscoveryFailedError(err)
}
