# 🔍 Kasten Discovery Report v1.0 - Enhanced for Kasten 7.5+ & 8.0+

## Overview

The **Kasten Discovery Report v1.0** is an advanced discovery and audit tool for Kasten K10 deployments. **Specifically optimized for Kasten K10 versions 7.5.1 to 8.0.8** and designed for **OpenShift 4.12, 4.14, 4.16, and 4.18**.

## ✨ Main Features

### 🆕 **New features in Kasten 7.5+ and 8.0+**
- **🛡️ Threat Protection**: Ransomware detection, ML anomalies, integrity verification  
- **📋 Compliance Reports**: SOX, GDPR, HIPAA with automated scoring  
- **🔄 Lifecycle Management**: Retention, archiving, smart deletion  
- **🔐 Advanced RBAC Analysis**: Privilege audit, over-provisioning detection  
- **🔒 Reinforced Immutability**: At-rest encryption, integrity verification  

### 🔒 **Advanced Security Analysis**
- **Extended immutability audit**: Support for new 7.5+ and 8.0+ APIs  
- **Regulatory compliance**: Quantified scoring with recommendations  
- **Threat detection**: Real-time ransomware protection  
- **Risk assessment**: Quantified security metrics  
- **Full audit trail**: Traceability for legal compliance  

### 🏭 **Native OpenShift Support**
- **Automatic detection**: OpenShift vs Kubernetes  
- **Specialized resources**: Routes, SCCs, storage classes  
- **Security integration**: Privilege analysis, constraints  
- **Optimized performance**: Native OpenShift APIs  

## 🚀 Quick Installation

### **Strict Prerequisites**
```bash
# REQUIRED Kasten versions
Kasten K10 7.5.1+ ✅ (absolute minimum)
Kasten K10 8.0.8  ✅ (recommended version)

# Unsupported versions
Kasten K10 < 7.5.1 ❌ (missing APIs)

# Version check
oc get pods -n kasten-io -l app.kubernetes.io/name=k10 -o jsonpath='{.items[0].spec.containers[0].image}'
```

### **Setup for new versions**
```bash
# 1. Project with extended support
mkdir kasten-discovery-enhanced && cd kasten-discovery-enhanced

# 2. Initialization with new dependencies
go mod init kasten-discovery
go get k8s.io/client-go@v0.28.4
go get k8s.io/apimachinery@v0.28.4
go get k8s.io/api@v0.28.4
go get k8s.io/api/rbac/v1  # For advanced RBAC

# 3. Extended RBAC required
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kasten-discovery-enhanced
rules:
# New Kasten 7.5+ APIs
- apiGroups: ["compliance.kio.kasten.io"]
  resources: ["compliancereports"]
  verbs: ["get", "list"]
- apiGroups: ["lifecycle.kio.kasten.io"]
  resources: ["datalifecyclepolicies"]
  verbs: ["get", "list"]
# New Kasten 8.0+ APIs
- apiGroups: ["security.kio.kasten.io"]
  resources: ["threatprotections"]
  verbs: ["get", "list"]
# RBAC analysis
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
EOF

# 4. Run with version validation
go run main.go kasten-io --export-json
```

## 📊 Enhanced Output Examples

### **Console with new features**
```
🔍 Kasten Discovery Report v1.0
   Supported Kasten versions: 7.5.1 - 8.0.8

🔍 Gathering Kasten K10 information...
   ✅ Kasten version 8.0.8 detected (features: enhanced-immutability, compliance-reporting, data-lifecycle-management, threat-protection, ransomware-protection, anomaly-detection, integrity-verification, advanced-rbac)
   
📊 Discovery Summary:
   📋 Kasten Version: 8.0.8 (8.0.8)
   🆕 Enhanced Features: threat-protection, compliance-reporting, advanced-rbac
   🛡️ Threat Protection: Enabled (0 threats detected)
   📋 Compliance Reports: 3 (avg score: 94%)
   🔄 Data Lifecycle Policies: 2 (1.2TB archived)
   🔐 RBAC Analysis: 2 security issues detected
```

### **New available metrics**
```json
{
  "kastenVersionParsed": {
    "major": 8, "minor": 0, "patch": 8,
    "supportedFeatures": ["threat-protection", "compliance-reporting", "advanced-rbac"]
  },
  "threatProtection": {
    "enabled": true,
    "ransomwareProtection": true,
    "threatsDetected": 0,
    "lastScan": "2025-09-06 14:30:00"
  },
  "complianceReports": [
    {
      "name": "sox-compliance",
      "complianceScore": 98,
      "violations": ["minor-retention-issue"]
    }
  ]
}
```

---

## ✨ Main Features (Extended)

### 🔒 **Advanced Security Analysis**
- **Immutability Audit**: S3 Object Lock, Azure Blob, VBR, WORM  
- **Regulatory compliance**: Governance vs Compliance modes  
- **Legal holds**: Tracking regulatory holds  
- **Violation analysis**: Identification of security gaps  

### 🏭 **Native OpenShift Support**
- **Automatic detection**: OpenShift vs vanilla Kubernetes  
- **OpenShift Routes**: Route collection with TLS analysis  
- **Security Context Constraints**: Audit of Kasten SCCs  
- **Storage classes**: Support for ODF, AWS, Azure, GCP  

### 🔄 **Disaster Recovery**
- **Cross-cluster status**: Replication health  
- **RTO/RPO metrics**: Replication lag and failover readiness  
- **DR tests**: History and recommendations  

---

## 📦 Deliverables

### **1. Main script**: `main.go`
```bash
# Full source code with all features
# Size: ~2000 lines
# Functions: 50+ complete functions
```

### **2. User Guide**: Complete guide with examples
```bash
# Installation, configuration, usage
# OpenShift troubleshooting
# Advanced use cases
```

### **3. Example Report**: Interactive HTML dashboard
```bash
# Responsive web interface
# Realistic demo data
# Mobile compatible
```

---

## 🚨 Troubleshooting

### **Common Errors**

#### **Permission denied**
```bash
# Solution: Verify RBAC
oc auth can-i get pods -n kasten-io
oc adm policy add-cluster-role-to-user cluster-reader $(oc whoami)
```

#### **CRDs not found**
```bash
# Solution: Verify Kasten installation
oc get crd | grep kasten
oc get operators -n kasten-io
```

#### **Connection timeout**
```bash
# Solution: Increase timeout
export KASTEN_TIMEOUT=120
```

#### **Proxy/Network**
```bash
# Solution: Configure proxy
export HTTP_PROXY=http://proxy:8080
export NO_PROXY=.cluster.local,.svc,localhost
```

---

## 📈 Use Cases

### **1. Security Audit**
```bash
# Immutability report
jq '.ImmutabilityConfig[] | select(.ImmutabilityStatus!="ENABLED")' data.json

# Compliance analysis
jq '.ClusterSummary.ImmutableProfiles / .ClusterSummary.TotalProfiles * 100' data.json
```

### **2. Automated Monitoring**
```bash
#!/bin/bash
# Daily monitoring script
./kasten-discovery kasten-io --export-json
FAILED_ACTIONS=$(jq '.ClusterSummary.FailedActions' kasten-discovery-data-kasten-io.json)
if [ "$FAILED_ACTIONS" -gt 0 ]; then
    echo "ALERT: $FAILED_ACTIONS failed actions detected"
    # Send notification
fi
```

### **3. Executive Report**
```bash
# Generate PDF report
wkhtmltopdf kasten-discovery-report-kasten-io.html executive-report.pdf

# Key metrics for dashboard
jq '{
  platform: .ClusterInfo.Platform,
  kasten_version: .KastenVersion,
  dr_enabled: .KastenDREnabled,
  immutability_coverage: (.ClusterSummary.ImmutableProfiles / .ClusterSummary.TotalProfiles * 100),
  backup_success_rate: (((.ClusterSummary.RecentActions - .ClusterSummary.FailedActions) / .ClusterSummary.RecentActions) * 100)
}' kasten-discovery-data-kasten-io.json
```

---

## 📞 Support
Bertrand Castagnet, EMEA TAM

### **Documentation**
WIP

### **Community**
- GitHub Issues for bugs and feature requests   
- Official Kasten K10 documentation
- Official Redhat Openshift documentation

---

**Developed by the Kasten community**  
Version 1.0 | Compatible with OpenShift 4.12-4.18 | September 2025
