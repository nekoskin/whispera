#!/bin/bash
# Build functions - Fully automated build system
# Source: source "$(dirname "$0")/lib/build.sh"

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"
# shellcheck source=go-module.sh
source "$SCRIPT_DIR/go-module.sh"

# Load configuration
CONFIG_FILE="$(dirname "$SCRIPT_DIR")/config/deploy.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Auto-setup: Ensure Go is installed and configured
auto_setup_go() {
    local work_dir="${1:-$(pwd)}"
    local min_version="${GO_MIN_VERSION:-1.16}"
    local target_version="${GO_VERSION:-1.23.4}"
    
    log_info "Checking Go installation..."
    
    # Prefer /usr/local/go/bin/go (newer version)
    if [[ -f "/usr/local/go/bin/go" ]]; then
        export PATH="/usr/local/go/bin:$PATH"
        export GOROOT="/usr/local/go"
        log_info "Using Go from /usr/local/go/bin/go"
    fi
    
    # Check if Go exists
    if ! command_exists go; then
        log_warning "Go not found in PATH, checking common locations..."
        local go_paths=(
            "/usr/local/go/bin/go"
            "/usr/bin/go"
            "$HOME/go/bin/go"
        )
        
        local found_go=""
        for path in "${go_paths[@]}"; do
            if [[ -f "$path" ]] && "$path" version &>/dev/null; then
                found_go="$path"
                export PATH="$(dirname "$path"):$PATH"
                log_info "Found Go at: $path"
                break
            fi
        done
        
        if [[ -z "$found_go" ]]; then
            log_error "Go is not installed. Please install Go ${target_version} or higher."
            log_info "Installation instructions: https://golang.org/doc/install"
            return 1
        fi
    fi
    
    # Get current Go version
    local current_go
    current_go=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/go//' || echo "0.0.0")
    log_info "Current Go version: ${current_go}"
    
    # Check if version is sufficient
    if [[ "$(printf '%s\n' "$min_version" "$current_go" | sort -V | head -n1)" != "$min_version" ]]; then
        log_error "Go version ${current_go} is too old (minimum: ${min_version})"
        log_error "Please install Go ${target_version} or higher"
        return 1
    fi
    
    # Verify Go version using ensure_go_installed if available
    if command_exists ensure_go_installed; then
        if ! ensure_go_installed "$min_version" "$target_version"; then
            log_warning "Go version check had issues, but continuing..."
        fi
    fi
    
    # Setup Go environment
    export GO111MODULE=on
    export CGO_ENABLED=0
    export GOTOOLCHAIN=local
    export GOFLAGS="-mod=mod"
    unset GOPATH 2>/dev/null || true
    unset GOWORK 2>/dev/null || true
    
    safe_cd "$work_dir"
    
    # Auto-fix go.mod
    if [[ -f "go.mod" ]]; then
        log_info "Auto-fixing go.mod..."
        fix_go_mod_version "go.mod" "1.23" "${GO_TOOLCHAIN:-go1.23.4}"
        fix_dependency_versions "go.mod" "go"
    fi
    
    # Auto-download dependencies
    log_info "Downloading Go dependencies..."
    go mod download 2>&1 || {
        log_warning "go mod download had issues, running go mod tidy..."
        go mod tidy 2>&1 || true
    }
    
    return 0
}

# Auto-setup: Verify project structure
auto_setup_project() {
    local work_dir="${1:-$(pwd)}"
    
    safe_cd "$work_dir"
    
    log_info "Verifying project structure..."
    
    # Check critical files
    local missing_files=()
    
    if [[ ! -f "go.mod" ]]; then
        missing_files+=("go.mod")
    fi
    
    if [[ ! -d "cmd/server" ]]; then
        missing_files+=("cmd/server")
    fi
    
    if [[ ! -d "cmd/client" ]]; then
        missing_files+=("cmd/client")
    fi
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        log_error "Missing critical files/directories:"
        for file in "${missing_files[@]}"; do
            log_error "  - $file"
        done
        return 1
    fi
    
    # Fix project structure if needed (server in wrong location)
    if [[ -d "server" ]] && [[ ! -d "internal/server" ]]; then
        log_info "Fixing project structure: moving server to internal/server..."
        mkdir -p internal
        mv server internal/ || {
            log_error "Failed to move server directory"
            return 1
        }
    fi
    
    log_success "Project structure verified"
    return 0
}

# Build server with full auto-setup
build_server() {
    local work_dir="${1:-$(pwd)}"
    local output_file="${2:-whispera-server}"
    local go_cmd="${3:-go}"
    local auto_setup="${4:-true}"
    
    log_info "Building Whispera server..."
    
    safe_cd "$work_dir"
    
    # Auto-setup if enabled
    if [[ "$auto_setup" == "true" ]]; then
        auto_setup_project "$work_dir" || error_exit "Project setup failed"
        auto_setup_go "$work_dir" || error_exit "Go setup failed"
    fi
    
    # Verify module
    if ! verify_go_module "$work_dir" "$go_cmd" "none"; then
        log_warning "Module verification had issues, attempting to fix..."
        fix_go_mod_version "go.mod"
        fix_dependency_versions "go.mod" "$go_cmd"
        go mod tidy 2>&1 || true
    fi
    
    # Set build environment
    export GO111MODULE=on
    export CGO_ENABLED=0
    export GOTOOLCHAIN=local
    export GOFLAGS="-mod=mod"
    unset GOPATH 2>/dev/null || true
    unset GOWORK 2>/dev/null || true
    
    # Fix go.mod if needed
    fix_go_mod_version "go.mod"
    fix_dependency_versions "go.mod" "$go_cmd"
    
    # Run go mod tidy
    log_info "Preparing dependencies..."
    go mod tidy 2>&1 || {
        log_warning "go mod tidy had warnings, continuing..."
    }
    
    # Build
    log_info "Compiling server..."
    local build_output
    if ! build_output=$("$go_cmd" build -mod=mod -o "$output_file" ./cmd/server 2>&1); then
        log_error "Build failed:"
        echo "$build_output" >&2
        
        # Try to fix and rebuild
        log_info "Attempting to fix issues and rebuild..."
        fix_go_mod_version "go.mod"
        fix_dependency_versions "go.mod" "$go_cmd"
        go mod tidy 2>&1 || true
        go mod download 2>&1 || true
        
        if ! build_output=$("$go_cmd" build -mod=mod -o "$output_file" ./cmd/server 2>&1); then
            error_exit "Server build failed after retry"
        fi
    fi
    
    # Verify binary was created
    if [[ ! -f "$output_file" ]]; then
        error_exit "Binary not created: $output_file"
    fi
    
    local size
    size=$(ls -lh "$output_file" | awk '{print $5}')
    log_success "Server built successfully: $size"
}

# Build client with full auto-setup
build_client() {
    local work_dir="${1:-$(pwd)}"
    local output_file="${2:-whispera-client}"
    local go_cmd="${3:-go}"
    local auto_setup="${4:-true}"
    
    log_info "Building Whispera client..."
    
    safe_cd "$work_dir"
    
    # Auto-setup if enabled
    if [[ "$auto_setup" == "true" ]]; then
        auto_setup_project "$work_dir" || error_exit "Project setup failed"
        auto_setup_go "$work_dir" || error_exit "Go setup failed"
    fi
    
    # Verify module
    if ! verify_go_module "$work_dir" "$go_cmd" "none"; then
        log_warning "Module verification had issues, attempting to fix..."
        fix_go_mod_version "go.mod"
        fix_dependency_versions "go.mod" "$go_cmd"
        go mod tidy 2>&1 || true
    fi
    
    # Set build environment
    export GO111MODULE=on
    export CGO_ENABLED=0
    export GOTOOLCHAIN=local
    export GOFLAGS="-mod=mod"
    unset GOPATH 2>/dev/null || true
    unset GOWORK 2>/dev/null || true
    
    # Fix go.mod if needed
    fix_go_mod_version "go.mod"
    fix_dependency_versions "go.mod" "$go_cmd"
    
    # Run go mod tidy
    log_info "Preparing dependencies..."
    go mod tidy 2>&1 || {
        log_warning "go mod tidy had warnings, continuing..."
    }
    
    # Build
    log_info "Compiling client..."
    local build_output
    if ! build_output=$("$go_cmd" build -mod=mod -o "$output_file" ./cmd/client 2>&1); then
        log_error "Build failed:"
        echo "$build_output" >&2
        
        # Try to fix and rebuild
        log_info "Attempting to fix issues and rebuild..."
        fix_go_mod_version "go.mod"
        fix_dependency_versions "go.mod" "$go_cmd"
        go mod tidy 2>&1 || true
        go mod download 2>&1 || true
        
        if ! build_output=$("$go_cmd" build -mod=mod -o "$output_file" ./cmd/client 2>&1); then
            error_exit "Client build failed after retry"
        fi
    fi
    
    # Verify binary was created
    if [[ ! -f "$output_file" ]]; then
        error_exit "Binary not created: $output_file"
    fi
    
    local size
    size=$(ls -lh "$output_file" | awk '{print $5}')
    log_success "Client built successfully: $size"
}

# Build all components automatically
build_all() {
    local work_dir="${1:-$(pwd)}"
    local output_dir="${2:-bin}"
    local go_cmd="${3:-go}"
    
    log_info "Starting automated build process..."
    
    safe_cd "$work_dir"
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Auto-setup
    auto_setup_project "$work_dir" || error_exit "Project setup failed"
    auto_setup_go "$work_dir" || error_exit "Go setup failed"
    
    # Build server
    build_server "$work_dir" "$output_dir/whispera-server" "$go_cmd" "false"
    
    # Build client
    build_client "$work_dir" "$output_dir/whispera-client" "$go_cmd" "false"
    
    # Build keygen
    log_info "Building keygen..."
    if go build -mod=mod -o "$output_dir/whispera-keygen" ./cmd/keygen 2>&1; then
        log_success "Keygen built successfully"
    else
        log_warning "Keygen build failed (non-critical)"
    fi
    
    log_success "All components built successfully in $output_dir/"
    ls -lh "$output_dir/" 2>/dev/null || true
}

