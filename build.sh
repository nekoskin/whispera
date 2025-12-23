#!/bin/bash
# Whispera Automated Build Script
# Fully automated build system - no user interaction required

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Source build functions
if [[ -f "scripts/lib/build.sh" ]]; then
    # shellcheck source=scripts/lib/build.sh
    source "scripts/lib/build.sh"
else
    echo "Error: scripts/lib/build.sh not found" >&2
    exit 1
fi

# Main build function
main() {
    log_info "🚀 Whispera Automated Build System"
    log_info "===================================="
    echo ""
    
    # Build all components
    build_all "$SCRIPT_DIR" "bin" "go"
    
    echo ""
    log_success "✅ Build completed successfully!"
    echo ""
    log_info "Built binaries:"
    ls -lh bin/ 2>/dev/null || ls -lh . | grep whispera || true
    echo ""
    log_info "Next steps:"
    log_info "  • Server: ./bin/whispera-server -listen :51820 -static-key YOUR_KEY"
    log_info "  • Client: ./bin/whispera-client -config client_config.yaml"
    log_info "  • Keygen: ./bin/whispera-keygen -mode x25519"
}

# Run main function
main "$@"

