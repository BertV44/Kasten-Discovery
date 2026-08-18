package scan

// K10's own configuration: how it was installed, not what it protects.
//
// Two sources, in the order KDL.sh consults them:
//
//   1. The Helm release object in the Kasten namespace, which holds the values
//      the operator supplied at install time. This is the authoritative answer
//      and the only one that covers settings K10 never writes anywhere else.
//   2. The k10-config ConfigMap, for installs configured through ConfigMap
//      overrides rather than Helm values, and for any run where the Helm read was
//      skipped or refused.
//
// Where neither answers, a handful of settings are inferred from objects already
// collected -- a FIPS environment variable on the catalog deployment, the
// presence of a K10 NetworkPolicy. Those fallbacks run only when the Helm values
// are unavailable, exactly as in the shell: a Helm value of false is an answer,
// and overriding it with a guess would turn a deliberate setting into a
// detection artefact.
//
// k10Configuration.source records which of the two answered, because a section
// full of defaults and a section full of read values look identical otherwise.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	kdl "github.com/BertV44/Kasten-Discovery/internal/schema"
)

// Config value sources, as they appear in k10Configuration.source. The first
// three are KDL.sh's spellings; there is no "helm-cli" here because this
// collector talks to the API server rather than shelling out to helm.
const (
	sourceHelmSecret = "helm-secret"
	sourceConfigMap  = "configmap"
	sourceSkipped    = "skipped"
	sourceNone       = "none"
)

// k10ConfigMapName is the ConfigMap K10 writes its effective settings to, and
// the fallback source for every dotted key below.
const k10ConfigMapName = "k10-config"

// installConfig is the merged view of the two sources.
type installConfig struct {
	// helm is the decoded user-supplied Helm values, nested as they were written.
	helm map[string]any
	// cm is the k10-config ConfigMap's data, whose keys are already the dotted
	// paths ("limiter.csiSnapshotsPerCluster").
	cm map[string]string
	// source names which of the two produced the Helm-level values.
	source string
}

// usable reports whether either source produced values. When neither did, every
// field in the section is a default rather than a reading, and the section is
// declared unpopulated: a page of K10's default limits presented as this
// cluster's settings is a report that says nothing while looking complete.
func (c installConfig) usable() bool {
	return c.source == sourceHelmSecret || c.source == sourceConfigMap
}

// helmAvailable reports whether the authoritative source answered. The
// inference fallbacks are gated on this rather than on individual fields, so a
// deliberate `false` in the Helm values is never overridden by a detection.
func (c installConfig) helmAvailable() bool { return c.source == sourceHelmSecret }

// str reads a dotted path from the Helm values, then from the ConfigMap.
func (c installConfig) str(path string) string {
	if v, ok := walkDotted(c.helm, path); ok {
		if s := scalarString(v); s != "" {
			return s
		}
	}
	if v, ok := c.cm[path]; ok && v != "" {
		return v
	}
	return ""
}

// strOr is str with a documented default. The default is what K10 itself does
// when the value is unset, so reporting it is reporting the effective setting --
// but the report says where its values came from, so a reader can tell a
// defaulted section from a read one.
func (c installConfig) strOr(path, fallback string) string {
	if v := c.str(path); v != "" {
		return v
	}
	return fallback
}

// boolean reads a dotted path as a boolean. An absent key is false, matching
// K10's own treatment of an unset feature flag.
func (c installConfig) boolean(path string) bool {
	return strings.EqualFold(c.str(path), "true")
}

// walkDotted resolves "auth.oidcAuth.enabled" against nested maps. Helm values
// arrive nested; the ConfigMap flattens the same paths into its keys, which is
// why both lookups exist.
func walkDotted(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, seg := range strings.Split(path, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = node[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// scalarString renders a Helm scalar. Numbers arrive as float64 from the JSON
// decoder and must not print as "8.000000"; anything that is not a scalar (a
// map, a list) is not a value this lookup can return.
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64, int64, int:
		if n, ok := toNumber(t); ok {
			return trimFloat(n)
		}
	}
	return ""
}

// loadInstallConfig assembles the two sources from the collection.
func loadInstallConfig(res Result, skipHelm bool) installConfig {
	cfg := installConfig{source: sourceNone}

	for _, o := range res.Items("k10ConfigMaps") {
		if name(o) != k10ConfigMapName {
			continue
		}
		cfg.cm = stringMap(mapAt(o.Object, "data"))
		break
	}

	if skipHelm {
		cfg.source = sourceSkipped
		return cfg
	}

	// Helm keeps one object per revision; the newest is the live one.
	var latest map[string]any
	latestVersion := -1
	for _, o := range res.Items("helmRelease") {
		version := helmReleaseVersion(name(o))
		if version < latestVersion {
			continue
		}
		values, ok := decodeHelmValues(o.Object)
		if !ok {
			continue
		}
		latest, latestVersion = values, version
	}
	if len(latest) > 0 {
		cfg.helm, cfg.source = latest, sourceHelmSecret
	} else if len(cfg.cm) > 0 {
		cfg.source = sourceConfigMap
	}
	return cfg
}

// helmReleaseVersion extracts the revision from "sh.helm.release.v1.k10.v7".
// A name that does not carry one sorts lowest rather than winning by accident.
func helmReleaseVersion(objectName string) int {
	idx := strings.LastIndex(objectName, ".v")
	if idx < 0 {
		return -1
	}
	if n, ok := toNumber(objectName[idx+2:]); ok {
		return int(n)
	}
	return -1
}

// decodeHelmValues unwraps a Helm release object down to the user-supplied
// values.
//
// The encoding is base64 of base64 of gzip of JSON: the outer layer is how the
// API serialises secret data, the inner two are Helm's own storage format. Only
// the `config` member -- the values the operator supplied -- is read out. The
// rest of the release payload, which includes the rendered manifests, is never
// looked at and never emitted.
func decodeHelmValues(obj map[string]any) (map[string]any, bool) {
	encoded, ok := str(obj, "data", "release")
	if !ok || encoded == "" {
		return nil, false
	}
	outer, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	inner, err := base64.StdEncoding.DecodeString(string(outer))
	if err != nil {
		// Some Helm versions store the payload gzipped without the second
		// base64 layer. Fall through to the gzip reader with what we have.
		inner = outer
	}
	zr, err := gzip.NewReader(bytes.NewReader(inner))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	// A release payload is a few hundred kilobytes; the cap is there so a
	// malformed or hostile stream cannot expand without bound.
	plain, err := io.ReadAll(io.LimitReader(zr, 32<<20))
	if err != nil {
		return nil, false
	}
	var release struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(plain, &release); err != nil {
		return nil, false
	}
	if len(release.Config) == 0 {
		return nil, false
	}
	return release.Config, true
}

// trimFloat renders a JSON number as an integer when it is one. The decoder
// hands every number over as a float64, and a concurrency limit printed as
// "8.000000" in a report is a value nobody can compare against a default.
func trimFloat(n float64) string {
	if n == float64(int64(n)) {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'f', -1, 64)
}

func stringMap(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s := scalarString(v); s != "" {
			out[k] = s
		}
	}
	return out
}

// buildK10Configuration fills the section from the merged sources.
func buildK10Configuration(res Result, r *kdl.Report, cfg installConfig) {
	k := &r.K10Configuration
	k.Source = cfg.source

	buildSecurity(res, r, cfg)
	buildDashboardAccess(res, r, cfg)

	k.ConcurrencyLimiters = kdl.K10ConfigurationConcurrencyLimiters{
		CSISnapshotsPerCluster:         cfg.strOr("limiter.csiSnapshotsPerCluster", "10"),
		SnapshotExportsPerCluster:      cfg.strOr("limiter.snapshotExportsPerCluster", "10"),
		SnapshotExportsPerAction:       cfg.strOr("limiter.snapshotExportsPerAction", "3"),
		VolumeRestoresPerCluster:       cfg.strOr("limiter.volumeRestoresPerCluster", "10"),
		VolumeRestoresPerAction:        cfg.strOr("limiter.volumeRestoresPerAction", "3"),
		VMSnapshotsPerCluster:          cfg.strOr("limiter.vmSnapshotsPerCluster", "1"),
		GenericVolumeBackupsPerCluster: cfg.strOr("limiter.genericVolumeBackupsPerCluster", "10"),
		ExecutorReplicas:               cfg.strOr("limiter.executorReplicas", "3"),
		ExecutorThreads:                cfg.strOr("limiter.executorThreads", "8"),
		WorkloadSnapshotsPerAction:     cfg.strOr("limiter.workloadSnapshotsPerAction", "5"),
		WorkloadRestoresPerAction:      cfg.strOr("limiter.workloadRestoresPerAction", "3"),
		// Kasten 9.0.2: caps concurrent volume retirement, which competes with
		// backup and export work on the same executor pool.
		VolumeRetiresPerCluster: cfg.strOr("limiter.volumeRetiresPerCluster", "10"),
	}

	k.Timeouts = kdl.K10ConfigurationTimeouts{
		BlueprintBackup:  cfg.strOr("timeout.blueprintBackup", "45"),
		BlueprintRestore: cfg.strOr("timeout.blueprintRestore", "600"),
		BlueprintHooks:   cfg.strOr("timeout.blueprintHooks", "20"),
		BlueprintDelete:  cfg.strOr("timeout.blueprintDelete", "45"),
		WorkerPodReady:   cfg.strOr("timeout.workerPodReady", "15"),
		JobWait:          cfg.strOr("timeout.jobWait", "600"),
		// The CSI snapshot timeouts are Kasten 9.0 values and live under
		// executor. rather than timeout., so they need their own paths. They
		// matter on slow storage: the default is the difference between a backup
		// that completes and one that times out.
		CSISnapshotCreation: cfg.strOr("executor.csiSnapshotCreationTimeout", "10m"),
		CSISnapshotReady:    cfg.strOr("executor.csiSnapshotReadyTimeout", "30m"),
	}

	k.Datastore = kdl.K10ConfigurationDatastore{
		ParallelUploads:        cfg.strOr("datastore.parallelUploads", "8"),
		ParallelDownloads:      cfg.strOr("datastore.parallelDownloads", "8"),
		ParallelBlockUploads:   cfg.strOr("datastore.parallelBlockUploads", "8"),
		ParallelBlockDownloads: cfg.strOr("datastore.parallelBlockDownloads", "8"),
		// Left empty when unset rather than given a number: the Kasten 9.0.2
		// release notes do not document the built-in cache defaults, and
		// inventing one would report a size nobody configured.
		ContentCacheSizeMB:  cfg.str("datastore.contentCacheSizeMB"),
		MetadataCacheSizeMB: cfg.str("datastore.metadataCacheSizeMB"),
	}

	defaultSize := cfg.strOr("global.persistence.size", "20Gi")
	k.Persistence = kdl.K10ConfigurationPersistence{
		DefaultSize:  defaultSize,
		CatalogSize:  cfg.strOr("global.persistence.catalog.size", defaultSize),
		JobsSize:     cfg.strOr("global.persistence.jobs.size", defaultSize),
		LoggingSize:  cfg.strOr("global.persistence.logging.size", defaultSize),
		MeteringSize: cfg.strOr("global.persistence.metering.size", "2Gi"),
		StorageClass: optional(cfg.str("global.persistence.storageClass")),
	}

	excluded := excludedApps(cfg)
	k.ExcludedApps = kdl.K10ConfigurationExcludedApps{Count: len(excluded), Items: excluded}

	k.Features.GVBSidecarInjection = gvbSidecarInjection(res, cfg)

	k.GarbageCollector = kdl.K10ConfigurationGarbageCollector{
		KeepMaxActions: cfg.strOr("garbagecollector.keepMaxActions", "1000"),
		DaemonPeriod:   cfg.strOr("garbagecollector.daemonPeriod", "21600"),
	}

	k.LogLevel = cfg.strOr("logLevel", "info")
	k.ClusterName = optional(cfg.str("clusterName"))
}

// excludedApps reads the global protection opt-out. It is accepted both as a
// list and as a comma-separated string, because the two sources spell it
// differently: Helm values carry a list, the ConfigMap carries one string.
func excludedApps(cfg installConfig) []string {
	if raw, ok := walkDotted(cfg.helm, "excludedApps"); ok {
		if list, isList := raw.([]any); isList {
			out := make([]string, 0, len(list))
			for _, v := range list {
				if s := strings.TrimSpace(scalarString(v)); s != "" {
					out = append(out, s)
				}
			}
			sort.Strings(out)
			return out
		}
	}
	joined := cfg.str("excludedApps")
	if joined == "" {
		return []string{}
	}
	var out []string
	for _, part := range strings.Split(joined, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// gvbSidecarInjection reports whether generic volume backup sidecars are
// injected. The webhook fallback runs only when the Helm values are
// unavailable: a Helm `false` is a decision, and a webhook left behind by a
// previous install would otherwise overrule it.
func gvbSidecarInjection(res Result, cfg installConfig) bool {
	if cfg.boolean("injectGenericVolumeBackupSidecar.enabled") {
		return true
	}
	if cfg.helmAvailable() {
		return false
	}
	for _, o := range res.Items("mutatingWebhooks") {
		if strings.Contains(strings.ToLower(name(o)), "generic-volume") {
			return true
		}
	}
	return false
}

// buildSecurity fills the security block: the part of this section that feeds
// the ransomware pillars, so every value here is either read or left at the
// answer that claims the least.
func buildSecurity(res Result, r *kdl.Report, cfg installConfig) {
	sec := &r.K10Configuration.Security

	sec.Authentication = authentication(cfg)
	sec.Encryption = encryption(cfg)

	sec.FIPSMode = cfg.boolean("fips.enabled")
	if !sec.FIPSMode && !cfg.helmAvailable() {
		// K10 passes the setting to its own containers, so the deployment is a
		// second witness when the Helm values are not readable.
		if v, ok := catalogEnv(res, "K10_FIPS_ENABLED"); ok && strings.EqualFold(v, "true") {
			sec.FIPSMode = true
		}
	}

	sec.NetworkPolicies = networkPolicies(res, cfg)
	sec.AuditLogging = auditLogging(cfg)
	sec.CustomCACertificate = optional(customCA(res, cfg))
	sec.SecurityContext = securityContext(res, cfg)

	// SCC only exists on OpenShift; reporting "no SCC" on plain Kubernetes would
	// read as a missing hardening step rather than an inapplicable one.
	if r.Platform == "OpenShift" {
		sec.Scc = cfg.boolean("scc.create")
		if !sec.Scc && !cfg.helmAvailable() {
			for _, o := range res.Items("scc") {
				lower := strings.ToLower(name(o))
				if strings.Contains(lower, "k10") || strings.Contains(lower, "kasten") {
					sec.Scc = true
					break
				}
			}
		}
	}
	sec.Vap = cfg.boolean("vap.kastenPolicyPermissions.enabled")
}

// authentication reports how the K10 dashboard is protected. An unauthenticated
// dashboard is a full restore capability exposed to anyone who can reach it, so
// "none" here is one of the report's most serious findings -- which is why the
// secret-based fallbacks exist rather than letting an unreadable Helm release
// produce it.
func authentication(cfg installConfig) kdl.K10ConfigurationSecurityAuthentication {
	for _, method := range []struct {
		flag, name, detail string
	}{
		{"auth.oidcAuth.enabled", "OIDC", "auth.oidcAuth.providerURL"},
		{"auth.ldap.enabled", "LDAP", "auth.ldap.host"},
		{"auth.openshift.enabled", "OpenShift OAuth", ""},
		{"auth.basicAuth.enabled", "Basic Auth", ""},
		{"auth.tokenAuth.enabled", "Token", ""},
	} {
		if !cfg.boolean(method.flag) {
			continue
		}
		details := ""
		if method.detail != "" {
			details = cfg.str(method.detail)
		}
		return kdl.K10ConfigurationSecurityAuthentication{Method: method.name, Details: details}
	}

	// Nothing said so -- and when neither source could be read, that is not
	// evidence of an unauthenticated dashboard, it is evidence that nobody
	// looked. KDL.sh answers "none" here and then probes for the auth secrets
	// K10 creates; this collector does not, because listing Secrets in the
	// Kasten namespace to test for two names is a wide read for a weak signal,
	// and the k10-config ConfigMap already carries the same auth keys the loop
	// above consults.
	//
	// So the third answer is "unknown". "none" is among the most alarming
	// findings the report can carry, and it must mean somebody checked.
	if !cfg.usable() {
		return kdl.K10ConfigurationSecurityAuthentication{Method: "unknown"}
	}
	return kdl.K10ConfigurationSecurityAuthentication{Method: "none"}
}

// encryption reports the KMS backing K10's primary key. Without one the key
// lives in a cluster secret, so an attacker who owns the cluster owns the
// backups' encryption as well -- which is why this feeds a ransomware pillar.
func encryption(cfg installConfig) kdl.K10ConfigurationSecurityEncryption {
	switch {
	case cfg.str("encryption.primaryKey.awsCmkKeyId") != "":
		return kdl.K10ConfigurationSecurityEncryption{Provider: "AWS KMS", Details: optional("CMK configured")}
	case cfg.str("encryption.primaryKey.azureKeyVaultURL") != "":
		detail := cfg.strOr("encryption.primaryKey.azureKeyVaultKeyName", "configured")
		return kdl.K10ConfigurationSecurityEncryption{Provider: "Azure Key Vault", Details: optional(detail)}
	case cfg.str("encryption.primaryKey.vaultTransitPath") != "":
		path := cfg.str("encryption.primaryKey.vaultTransitPath")
		return kdl.K10ConfigurationSecurityEncryption{
			Provider: "HashiCorp Vault", Details: optional("transit: " + path)}
	}
	if !cfg.helmAvailable() {
		if cfg.cm["vault.address"] != "" {
			return kdl.K10ConfigurationSecurityEncryption{
				Provider: "HashiCorp Vault", Details: optional("detected")}
		}
	}
	return kdl.K10ConfigurationSecurityEncryption{Provider: "none"}
}

// auditLogging reports whether K10 records who did what, and where those records
// go. Without it a ransomware investigation has no account of the restore
// attempts that preceded it.
func auditLogging(cfg installConfig) kdl.K10ConfigurationSecurityAuditLogging {
	var targets []string
	if cfg.boolean("siem.logging.cluster.enabled") {
		targets = append(targets, "stdout")
	}
	if cfg.boolean("siem.logging.cloud.awsS3.enabled") {
		targets = append(targets, "S3")
	}
	if len(targets) > 0 {
		return kdl.K10ConfigurationSecurityAuditLogging{
			Enabled: true, Targets: optional(strings.Join(targets, ", "))}
	}
	if !cfg.helmAvailable() {
		for key, value := range cfg.cm {
			if strings.HasPrefix(key, "siem.") && strings.HasSuffix(key, "enabled") &&
				strings.EqualFold(value, "true") {
				return kdl.K10ConfigurationSecurityAuditLogging{
					Enabled: true, Targets: optional("detected")}
			}
		}
	}
	return kdl.K10ConfigurationSecurityAuditLogging{}
}

func networkPolicies(res Result, cfg installConfig) bool {
	// Unlike the other flags this one distinguishes an explicit false from an
	// absent key: networkPolicy.create is a value operators do set to false
	// deliberately, and the object-presence fallback would flip it.
	if v := cfg.str("networkPolicy.create"); v != "" {
		return strings.EqualFold(v, "true")
	}
	return len(res.Items("k10NetworkPolicies")) > 0
}

func customCA(res Result, cfg installConfig) string {
	if v := cfg.str("cacertconfigmap.name"); v != "" {
		return v
	}
	if cfg.helmAvailable() {
		return ""
	}
	// A CA bundle reaches the catalog pod as a mounted ConfigMap, so the volume
	// list is where an install configured outside Helm shows it.
	for _, d := range res.Items("k10Deployments") {
		if d.GetLabels()["component"] != "catalog" {
			continue
		}
		for _, v := range slice(d.Object, "spec", "template", "spec", "volumes") {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			cmName, found := str(vm, "configMap", "name")
			if !found {
				continue
			}
			lower := strings.ToLower(cmName)
			if strings.Contains(lower, "ca") || strings.Contains(lower, "cert") ||
				strings.Contains(lower, "ssl") {
				return cmName
			}
		}
	}
	return ""
}

// securityContext reports the UID K10's pods run as. The 1000/1000 default is
// K10's own, so it is reported rather than left blank -- but only after both the
// values and the deployment have been asked.
func securityContext(res Result, cfg installConfig) kdl.K10ConfigurationSecuritySecurityContext {
	runAsUser := cfg.str("services.securityContext.runAsUser")
	fsGroup := cfg.str("services.securityContext.fsGroup")
	if runAsUser == "" {
		for _, d := range res.Items("k10Deployments") {
			if d.GetLabels()["component"] != "catalog" {
				continue
			}
			sc := mapAt(d.Object, "spec", "template", "spec", "securityContext")
			if v := scalarString(sc["runAsUser"]); v != "" {
				runAsUser = v
			}
			if v := scalarString(sc["fsGroup"]); v != "" && fsGroup == "" {
				fsGroup = v
			}
			break
		}
	}
	if runAsUser == "" {
		runAsUser = "1000"
	}
	if fsGroup == "" {
		fsGroup = "1000"
	}
	return kdl.K10ConfigurationSecuritySecurityContext{RunAsUser: runAsUser, FsGroup: fsGroup}
}

// buildDashboardAccess reports how the K10 dashboard is reachable from outside
// the cluster. Together with the authentication method it is the exposure
// picture: an Ingress plus no authentication is a restore console on the
// internet.
func buildDashboardAccess(res Result, r *kdl.Report, cfg installConfig) {
	da := &r.K10Configuration.DashboardAccess
	da.Method = "ClusterIP"

	if ingresses := res.Items("k10Ingresses"); len(ingresses) > 0 {
		da.Method = "Ingress"
		for _, rule := range slice(ingresses[0].Object, "spec", "rules") {
			rm, ok := rule.(map[string]any)
			if !ok {
				continue
			}
			if host, found := str(rm, "host"); found && host != "" {
				da.Host = host
				break
			}
		}
		return
	}
	if routes := res.Items("routes"); len(routes) > 0 {
		da.Method = "Route"
		da.Host = strOr(routes[0].Object, "", "spec", "host")
		return
	}
	for _, svc := range res.Items("k10Services") {
		if name(svc) == "gateway-ext" {
			da.Method = "External Gateway"
			da.Host = cfg.strOr("externalGateway.fqdn.name", "LoadBalancer")
			return
		}
	}
}

// catalogEnv reads one environment variable off the catalog deployment's first
// container, which is where K10 passes its own build-time settings.
func catalogEnv(res Result, key string) (string, bool) {
	for _, d := range res.Items("k10Deployments") {
		if d.GetLabels()["component"] != "catalog" {
			continue
		}
		for _, c := range slice(d.Object, "spec", "template", "spec", "containers") {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			for _, e := range slice(cm, "env") {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if n, _ := str(em, "name"); n != key {
					continue
				}
				if v, found := str(em, "value"); found {
					return v, true
				}
			}
		}
	}
	return "", false
}

// buildNonDefaultSettings counts the settings that differ from K10's defaults.
//
// It is the section's headline: an operator reading a page of numbers cannot
// tell which of them somebody chose. The comparison is against the same defaults
// the shell renderer uses, so a setting flagged as tuned here is the set the
// shell flags too.
//
// It runs after the rest of the section is filled, because it compares the
// values that were actually reported rather than re-reading the sources.
func buildNonDefaultSettings(r *kdl.Report) {
	k := &r.K10Configuration
	var tuned []string
	check := func(label, got, want string) {
		if got != want {
			tuned = append(tuned, label)
		}
	}

	lim := k.ConcurrencyLimiters
	check("csiSnapshots", lim.CSISnapshotsPerCluster, "10")
	check("exports", lim.SnapshotExportsPerCluster, "10")
	check("restores", lim.VolumeRestoresPerCluster, "10")
	check("vmSnapshots", lim.VMSnapshotsPerCluster, "1")
	check("executorReplicas", lim.ExecutorReplicas, "3")
	check("executorThreads", lim.ExecutorThreads, "8")

	to := k.Timeouts
	check("bpBackup", to.BlueprintBackup, "45")
	check("bpRestore", to.BlueprintRestore, "600")
	check("workerPod", to.WorkerPodReady, "15")
	check("jobWait", to.JobWait, "600")

	check("uploads", k.Datastore.ParallelUploads, "8")
	check("downloads", k.Datastore.ParallelDownloads, "8")
	check("logLevel", k.LogLevel, "info")

	k.NonDefaultSettings = kdl.K10ConfigurationNonDefaultSettings{
		Count: len(tuned),
		Items: optional(strings.Join(tuned, ", ")),
	}
}
