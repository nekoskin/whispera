#!/bin/bash
# Go module management functions
# Source: source "$(dirname "$0")/lib/go-module.sh"

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# Fix go.mod version issues
fix_go_mod_version() {
    local go_mod_file="${1:-go.mod}"
    local target_version="${2:-1.23}"
    local toolchain_version="${3:-go1.23.4}"
    
    if [[ ! -f "$go_mod_file" ]]; then
        log_error "go.mod file not found: $go_mod_file"
        return 1
    fi
    
    local needs_fix=false
    
    # Check for invalid Go version
    if grep -q "go 1\.24" "$go_mod_file" 2>/dev/null || grep -q "toolchain go1\.24" "$go_mod_file" 2>/dev/null; then
        needs_fix=true
        log_info "Fixing go.mod: removing invalid Go 1.24 references..."
        
        # Fix Go version
        sed -i.bak "s/go 1\.24\..*/go ${target_version}/g" "$go_mod_file" 2>/dev/null || true
        sed -i.bak "s/go 1\.24[^0-9]/go ${target_version}/g" "$go_mod_file" 2>/dev/null || true
        
        # Remove invalid toolchain
        sed -i.bak '/^toolchain go1\.24/d' "$go_mod_file" 2>/dev/null || true
        
        # Add correct toolchain if missing
        if ! grep -q "^toolchain" "$go_mod_file" 2>/dev/null; then
            awk -v version="$toolchain_version" '/^go '"${target_version}"'$/ {print; print "toolchain " version; next} {print}' "$go_mod_file" > "${go_mod_file}.tmp" && \
            mv "${go_mod_file}.tmp" "$go_mod_file" 2>/dev/null || {
                sed -i.bak "/^go ${target_version}\$/a\\
toolchain ${toolchain_version}" "$go_mod_file" 2>/dev/null || true
            }
        else
            # Replace existing toolchain
            sed -i.bak "s/^toolchain.*/toolchain ${toolchain_version}/g" "$go_mod_file" 2>/dev/null || true
        fi
        
        rm -f "${go_mod_file}.bak" 2>/dev/null || true
        log_success "go.mod version fixed"
    fi
    
    return 0
}

# Fix dependency versions incompatible with Go 1.23
fix_dependency_versions() {
    local go_mod_file="${1:-go.mod}"
    local go_cmd="${2:-go}"
    
    if [[ ! -f "$go_mod_file" ]]; then
        log_error "go.mod file not found: $go_mod_file"
        return 1
    fi
    
    # Load config for versions
    local config_file="$(dirname "$SCRIPT_DIR")/config/deploy.conf"
    if [[ -f "$config_file" ]]; then
        # shellcheck source=/dev/null
        source "$config_file"
    fi
    
    local crypto_version="${CRYPTO_VERSION:-v0.41.0}"
    local net_version="${NET_VERSION:-v0.43.0}"
    local sys_version="${SYS_VERSION:-v0.35.0}"
    local text_version="${TEXT_VERSION:-v0.28.0}"
    
    local needs_fix=false
    
    # Check and fix golang.org/x/crypto
    if grep -qE "golang.org/x/crypto[[:space:]]+v0\.(4[2-9]|[5-9])" "$go_mod_file" 2>/dev/null; then
        needs_fix=true
        log_info "Fixing golang.org/x/crypto version..."
        "$go_cmd" mod edit -replace="golang.org/x/crypto=golang.org/x/crypto@${crypto_version}" 2>/dev/null || true
        sed -i.bak "s|golang.org/x/crypto[[:space:]]*v0\.\(4[2-9]\|[5-9]\)\.[0-9]*|golang.org/x/crypto ${crypto_version}|g" "$go_mod_file" 2>/dev/null || true
    fi
    
    # Check and fix golang.org/x/net
    if grep -qE "golang.org/x/net[[:space:]]+v0\.(4[5-9]|[5-9])" "$go_mod_file" 2>/dev/null; then
        needs_fix=true
        log_info "Fixing golang.org/x/net version..."
        "$go_cmd" mod edit -replace="golang.org/x/net=golang.org/x/net@${net_version}" 2>/dev/null || true
        sed -i.bak "s|golang.org/x/net[[:space:]]*v0\.\(4[5-9]\|[5-9]\)\.[0-9]*|golang.org/x/net ${net_version}|g" "$go_mod_file" 2>/dev/null || true
    fi
    
    # Check and fix golang.org/x/sys
    if grep -qE "golang.org/x/sys[[:space:]]+v0\.(3[6-9]|[4-9])" "$go_mod_file" 2>/dev/null; then
        needs_fix=true
        log_info "Fixing golang.org/x/sys version..."
        "$go_cmd" mod edit -replace="golang.org/x/sys=golang.org/x/sys@${sys_version}" 2>/dev/null || true
        sed -i.bak "s|golang.org/x/sys[[:space:]]*v0\.\(3[6-9]\|[5-9]\)\.[0-9]*|golang.org/x/sys ${sys_version}|g" "$go_mod_file" 2>/dev/null || true
    fi
    
    # Check and fix golang.org/x/text
    if grep -qE "golang.org/x/text[[:space:]]+v0\.(2[9]|3[0-9]|[4-9])" "$go_mod_file" 2>/dev/null; then
        needs_fix=true
        log_info "Fixing golang.org/x/text version..."
        "$go_cmd" mod edit -replace="golang.org/x/text=golang.org/x/text@${text_version}" 2>/dev/null || true
        sed -i.bak "s|golang.org/x/text[[:space:]]*v0\.\(2[9]\|3[0-9]\|[4-9]\)\.[0-9]*|golang.org/x/text ${text_version}|g" "$go_mod_file" 2>/dev/null || true
    fi
    
    # Always add replace directives to override transitive dependencies
    if [[ "$needs_fix" == true ]]; then
        log_info "Adding replace directives for dependency overrides..."
        "$go_cmd" mod edit -replace="golang.org/x/crypto=golang.org/x/crypto@${crypto_version}" 2>/dev/null || true
        "$go_cmd" mod edit -replace="golang.org/x/net=golang.org/x/net@${net_version}" 2>/dev/null || true
        "$go_cmd" mod edit -replace="golang.org/x/sys=golang.org/x/sys@${sys_version}" 2>/dev/null || true
        "$go_cmd" mod edit -replace="golang.org/x/text=golang.org/x/text@${text_version}" 2>/dev/null || true
    fi
    
    rm -f "${go_mod_file}.bak" 2>/dev/null || true
    
    return 0
}

# Verify Go module is properly configured
verify_go_module() {
    local work_dir="${1:-$(pwd)}"
    local go_cmd="${2:-go}"
    local check_package="${3:-none}"
    
    log_debug "Verifying Go module in $work_dir"
    
    # Change to work directory
    if [[ -n "$work_dir" ]] && [[ "$work_dir" != "$(pwd)" ]]; then
        safe_cd "$work_dir"
    fi
    
    # Set Go environment
    export GO111MODULE=on
    export GOTOOLCHAIN=local
    export GOFLAGS="-mod=mod"
    unset GOPATH 2>/dev/null || true
    unset GOWORK 2>/dev/null || true
    
    # Check go.mod exists
    if [[ ! -f "go.mod" ]]; then
        log_error "go.mod not found in $(pwd)"
        return 1
    fi
    
    # Fix go.mod if needed
    fix_go_mod_version "go.mod"
    fix_dependency_versions "go.mod" "$go_cmd"
    
    # Verify module name
    local module_name
    module_name=$("$go_cmd" list -m 2>/dev/null || echo "")
    if [[ -z "$module_name" ]] || [[ "$module_name" != "whispera" ]]; then
        log_warning "Module not recognized as 'whispera' (found: '$module_name')"
        log_info "Running go mod tidy..."
        "$go_cmd" mod tidy 2>/dev/null || true
        module_name=$("$go_cmd" list -m 2>/dev/null || echo "")
        if [[ "$module_name" != "whispera" ]]; then
            log_error "Module verification failed"
            return 1
        fi
    fi
    
    log_debug "Module verified: $module_name"
    return 0
}

# Ensure Go is installed and correct version
ensure_go_installed() {
    local min_version="${1:-1.16}"
    local target_version="${2:-1.23.4}"
    
    if ! command_exists go; then
        log_error "Go is not installed. Install Go ${target_version} or higher."
        return 1
    fi
    
    local go_version
    go_version=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//' || echo "0.0.0")
    
    local major minor
    major=$(echo "$go_version" | cut -d. -f1)
    minor=$(echo "$go_version" | cut -d. -f2)
    local min_major min_minor
    min_major=$(echo "$min_version" | cut -d. -f1)
    min_minor=$(echo "$min_version" | cut -d. -f2)
    
    if [[ "$major" -lt "$min_major" ]] || ([[ "$major" -eq "$min_major" ]] && [[ "$minor" -lt "$min_minor" ]]); then
        log_warning "Go version $go_version is too old (minimum: $min_version)"
        return 1
    fi
    
    log_debug "Go version check passed: $go_version"
    return 0
}

