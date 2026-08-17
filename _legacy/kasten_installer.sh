#!/bin/bash
set -e

# Kasten Discovery Report - Installation Script
# Compatible with OpenShift 4.12, 4.14, 4.16, 4.18

VERSION="1.0"
TOOL_NAME="Kasten Discovery Report"

echo "🔍 $TOOL_NAME v$VERSION - Installation"
echo "   Target: OpenShift 4.12, 4.14, 4.16, 4.18"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check OpenShift/Kubernetes access
    if command -v oc &> /dev/null; then
        log_success "OpenShift CLI (oc) detected"
        
        # Check cluster access
        if oc whoami &> /dev/null; then
            CURRENT_USER=$(oc whoami)
            CURRENT_CONTEXT=$(oc config current-context 2>/dev/null || echo "unknown")
            log_success "Connected to cluster as: $CURRENT_USER"
            log_info "Current context: $CURRENT_CONTEXT"
            
            # Detect OpenShift version
            OCP_VERSION=$(oc get clusterversion -o jsonpath='{.items[0].status.desired.version}' 2>/dev/null || echo "unknown")
            if [[ "$OCP_VERSION" != "unknown" ]]; then
                log_success "OpenShift version: $OCP_VERSION"
                
                # Check if version is supported
                if [[ "$OCP_VERSION" =~ ^4\.(12|14|16|18) ]]; then
                    log_success "OpenShift version is supported ✅"
                else
                    log_warning "OpenShift version may not be fully tested with this tool"
                fi
            else
                log_warning "Could not detect OpenShift version (may be vanilla Kubernetes)"
            fi
        else
            log_error "Not connected to any cluster. Please login first:"
            log_info "  oc login <cluster-url>"
            exit 1
        fi
    elif command -v kubectl &> /dev/null; then
        log_warning "Using kubectl (OpenShift CLI not found)"
        log_info "Some OpenShift-specific features may not be available"
        
        if kubectl cluster-info &> /dev/null; then
            log_success "Connected to Kubernetes cluster"
        else
            log_error "Not connected to any cluster. Please configure kubectl first"
            exit 1
        fi
    else
        log_error "Neither oc nor kubectl found. Please install OpenShift CLI or kubectl."
        exit 1
    fi
}

# Check Kasten installation
check_kasten() {
    log_info "Checking Kasten K10 installation..."
    
    # Default namespace
    KASTEN_NAMESPACE="${KASTEN_NAMESPACE:-kasten-io}"
    
    # Check if namespace exists
    if oc get namespace "$KASTEN_NAMESPACE" &> /dev/null; then
        log_success "Kasten namespace '$KASTEN_NAMESPACE' found"
    else
        log_error "Kasten namespace '$KASTEN_NAMESPACE' not found"
        log_info "Available namespaces with 'kasten' in name:"
        oc get namespaces | grep -i kasten || log_warning "No namespaces with 'kasten' found"
        exit 1
    fi
    
    # Check Kasten pods
    KASTEN_PODS=$(oc get pods -n "$KASTEN_NAMESPACE" --no-headers 2>/dev/null | wc -l)
    if [[ "$KASTEN_PODS" -gt 0 ]]; then
        log_success "$KASTEN_PODS Kasten pods found in namespace '$KASTEN_NAMESPACE'"
        
        # Check pod status
        RUNNING_PODS=$(oc get pods -n "$KASTEN_NAMESPACE" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
        log_info "Running pods: $RUNNING_PODS/$KASTEN_PODS"
        
        if [[ "$RUNNING_PODS" -lt "$KASTEN_PODS" ]]; then
            log_warning "Not all Kasten pods are running. Report may be incomplete."
            oc get pods -n "$KASTEN_NAMESPACE" --field-selector=status.phase!=Running
        fi
    else
        log_error "No Kasten pods found in namespace '$KASTEN_NAMESPACE'"
        exit 1
    fi
    
    # Check Kasten CRDs
    KASTEN_CRDS=$(oc get crd | grep -c kasten 2>/dev/null || echo "0")
    if [[ "$KASTEN_CRDS" -gt 0 ]]; then
        log_success "$KASTEN_CRDS Kasten CRDs found"
    else
        log_warning "No Kasten CRDs found - some features may not work"
    fi
    
    # Try to detect Kasten version
    KASTEN_VERSION=$(oc get pods -n "$KASTEN_NAMESPACE" -l app.kubernetes.io/name=k10 -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null | cut -d':' -f2 || echo "unknown")
    if [[ "$KASTEN_VERSION" != "unknown" ]]; then
        log_success "Kasten K10 version: $KASTEN_VERSION"
    fi
}

# Check permissions
check_permissions() {
    log_info "Checking RBAC permissions..."
    
    # Required permissions
    declare -a REQUIRED_PERMS=(
        "get pods"
        "list pods"
        "get services"
        "list services"
        "get configmaps"
        "list configmaps" 
        "get secrets"
        "list secrets"
        "get persistentvolumeclaims"
        "list persistentvolumeclaims"
        "get events"
        "list events"
    )
    
    # Check each permission
    PERM_OK=0
    TOTAL_PERMS=${#REQUIRED_PERMS[@]}
    
    for perm in "${REQUIRED_PERMS[@]}"; do
        if oc auth can-i $perm -n "$KASTEN_NAMESPACE" &>/dev/null; then
            PERM_OK=$((PERM_OK + 1))
        else
            log_warning "Missing permission: $perm"
        fi
    done
    
    if [[ "$PERM_OK" -eq "$TOTAL_PERMS" ]]; then
        log_success "All basic permissions verified ($PERM_OK/$TOTAL_PERMS)"
    else
        log_warning "Some permissions missing ($PERM_OK/$TOTAL_PERMS)"
        log_info "You may need to run: oc adm policy add-cluster-role-to-user cluster-reader \$(oc whoami)"
    fi
    
    # Check Kasten-specific permissions
    if oc auth can-i get policies.config.kio.kasten.io -n "$KASTEN_NAMESPACE" &>/dev/null; then
        log_success "Kasten policy permissions verified"
    else
        log_warning "Cannot access Kasten policies - some features may not work"
    fi
    
    # Check OpenShift-specific permissions
    if oc auth can-i get routes.route.openshift.io -n "$KASTEN_NAMESPACE" &>/dev/null; then
        log_success "OpenShift route permissions verified"
    else
        log_warning "Cannot access OpenShift routes (normal on non-OpenShift)"
    fi
}

# Setup project
setup_project() {
    log_info "Setting up project..."
    
    PROJECT_DIR="kasten-discovery"
    
    if [[ -d "$PROJECT_DIR" ]]; then
        log_warning "Directory '$PROJECT_DIR' already exists"
        read -p "Do you want to continue and overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled"
            exit 0
        fi
    fi
    
    # Create project directory
    mkdir -p "$PROJECT_DIR"
    cd "$PROJECT_DIR"
    log_success "Created project directory: $PROJECT_DIR"
    
    # Initialize Go module
    if [[ ! -f "go.mod" ]]; then
        go mod init kasten-discovery
        log_success "Initialized Go module"
    else
        log_info "Go module already exists"
    fi
    
    # Install dependencies
    log_info "Installing Go dependencies..."
    go get k8s.io/client-go@v0.28.4
    go get k8s.io/apimachinery@v0.28.4
    go get k8s.io/api@v0.28.4
    log_success "Dependencies installed"
}

# Download main.go (in real scenario, this would download from repository)
create_main_file() {
    log_info "Creating main.go file..."
    
    # In a real scenario, you would download this from a repository
    # For now, we'll create a placeholder that instructs the user
    cat > main.go << 'EOF'
package main

import (
    "fmt"
    "log"
    "os"
)

func main() {
    fmt.Println("🔍 Kasten Discovery Report v1.0")
    fmt.Println("   Please copy the complete main.go source code from the provided artifact.")
    fmt.Println("   This placeholder file needs to be replaced with the full implementation.")
    
    if len(os.Args) < 2 {
        log.Fatal("Usage: go run main.go <namespace> [kubeconfig-path] [--export-json]")
    }
    
    fmt.Printf("   Target namespace: %s\n", os.Args[1])
    fmt.Println("   Status: ⚠️  Source code needed")
}
EOF
    
    log_warning "Placeholder main.go created"
    log_info "Please replace main.go with the complete source code from the provided artifact"
}

# Build project
build_project() {
    log_info "Building project..."
    
    if go build -o kasten-discovery main.go; then
        log_success "Project built successfully: ./kasten-discovery"
        
        # Make executable
        chmod +x kasten-discovery
        
        # Test run
        if ./kasten-discovery --help &>/dev/null || ./kasten-discovery kasten-io &>/dev/null; then
            log_success "Binary test passed"
        else
            log_warning "Binary test failed - may need complete source code"
        fi
    else
        log_error "Build failed"
        log_info "Make sure main.go contains the complete source code"
        return 1
    fi
}

# Create helper scripts
create_helpers() {
    log_info "Creating helper scripts..."
    
    # Quick run script
    cat > run.sh << EOF
#!/bin/bash
# Quick run script for Kasten Discovery
set -e

NAMESPACE=\${1:-kasten-io}
EXPORT_JSON=\${2:-false}

echo "🔍 Running Kasten Discovery Report..."
echo "   Namespace: \$NAMESPACE"

if [[ "\$EXPORT_JSON" == "true" || "\$EXPORT_JSON" == "--export-json" ]]; then
    ./kasten-discovery "\$NAMESPACE" --export-json
else
    ./kasten-discovery "\$NAMESPACE"
fi

echo ""
echo "📁 Generated files:"
ls -la kasten-discovery-* 2>/dev/null || echo "No files generated"
EOF
    chmod +x run.sh
    log_success "Created run.sh helper script"
    
    # Status check script
    cat > check-status.sh << EOF
#!/bin/bash
# Status check script for Kasten environment
set -e

NAMESPACE=\${1:-kasten-io}

echo "🔍 Kasten Environment Status Check"
echo "   Namespace: \$NAMESPACE"
echo ""

echo "📦 Pods Status:"
oc get pods -n "\$NAMESPACE" || echo "Cannot access namespace \$NAMESPACE"

echo ""
echo "🛡️ Policies:"
oc get policies.config.kio.kasten.io -n "\$NAMESPACE" 2>/dev/null | head -10 || echo "No policies found or no access"

echo ""
echo "📊 Storage Profiles:"
oc get profiles.config.kio.kasten.io -n "\$NAMESPACE" 2>/dev/null | head -10 || echo "No profiles found or no access"

echo ""
echo "⚡ Recent Actions (last 5):"
oc get runactions.actions.kio.kasten.io -n "\$NAMESPACE" 2>/dev/null | head -6 || echo "No actions found or no access"
EOF
    chmod +x check-status.sh
    log_success "Created check-status.sh helper script"
}

# Create documentation
create_docs() {
    log_info "Creating documentation..."
    
    cat > README.md << EOF
# Kasten Discovery Report v$VERSION

## Quick Start

\`\`\`bash
# Run discovery report
./run.sh kasten-io

# With JSON export
./run.sh kasten-io --export-json

# Check Kasten status
./check-status.sh kasten-io
\`\`\`

## Manual Usage

\`\`\`bash
# Basic usage
./kasten-discovery kasten-io

# With JSON export
./kasten-discovery kasten-io --export-json

# Custom kubeconfig
KUBECONFIG=/path/to/config ./kasten-discovery kasten-io
\`\`\`

## Files Generated

- \`kasten-discovery-report-<namespace>.html\` - Interactive dashboard
- \`kasten-discovery-data-<namespace>.json\` - Raw data (with --export-json)

## Troubleshooting

1. **Permission denied**: \`oc adm policy add-cluster-role-to-user cluster-reader \$(oc whoami)\`
2. **CRDs not found**: Check Kasten installation with \`./check-status.sh\`
3. **Build errors**: Ensure complete source code is in main.go

## Supported Platforms

- ✅ OpenShift 4.12
- ✅ OpenShift 4.14  
- ✅ OpenShift 4.16
- ✅ OpenShift 4.18
- ⚠️  Kubernetes (limited OpenShift features)

Generated by installation script v$VERSION
EOF
    
    log_success "Created README.md"
}

# Main installation flow
main() {
    echo "Starting installation process..."
    echo ""
    
    # Check prerequisites
    check_prerequisites
    echo ""
    
    # Check Kasten installation
    check_kasten
    echo ""
    
    # Check permissions
    check_permissions  
    echo ""
    
    # Setup project
    setup_project
    echo ""
    
    # Create main file (placeholder)
    create_main_file
    echo ""
    
    # Create helper scripts
    create_helpers
    echo ""
    
    # Create documentation
    create_docs
    echo ""
    
    log_success "Installation completed!"
    echo ""
    echo "📁 Project created in: $(pwd)"
    echo "📋 Next steps:"
    echo "   1. Replace main.go with complete source code from artifact"
    echo "   2. Build: go build -o kasten-discovery main.go" 
    echo "   3. Run: ./run.sh $KASTEN_NAMESPACE"
    echo ""
    echo "🔧 Helper commands:"
    echo "   ./check-status.sh        # Check Kasten environment"
    echo "   ./run.sh kasten-io       # Quick discovery run"
    echo "   cat README.md            # Read documentation"
    echo ""
    
    # Final validation
    log_info "Installation Summary:"
    log_success "✅ Prerequisites checked"
    log_success "✅ Kasten K10 detected in namespace: $KASTEN_NAMESPACE"
    log_success "✅ Project structure created"
    log_success "✅ Helper scripts generated"
    log_warning "⚠️  Main.go needs complete source code"
    echo ""
    
    log_info "🎯 Platform: $(oc get clusterversion -o jsonpath='{.items[0].status.desired.version}' 2>/dev/null | sed 's/^/OpenShift /' || echo 'Kubernetes')"
    log_success "Ready for Kasten Discovery Report generation!"
}

# Error handling
trap 'log_error "Installation failed at line $LINENO"' ERR

# Run main installation
main "$@" Go installation
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.19+ first."
        log_info "Install Go: https://golang.org/doc/install"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_success "Go $GO_VERSION detected"
    
    # Check