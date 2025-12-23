#!/bin/bash
# Common functions library for Whispera deployment scripts
# Source this file in other scripts: source "$(dirname "$0")/lib/common.sh"

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" >&2
    fi
}

# Error handling
error_exit() {
    log_error "$1"
    exit "${2:-1}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root
is_root() {
    [[ $EUID -eq 0 ]]
}

# Require root or sudo
require_root() {
    if ! is_root && ! sudo -n true 2>/dev/null; then
        error_exit "This operation requires root privileges. Run with sudo or as root."
    fi
}

# Safe directory change with error handling
safe_cd() {
    local dir="$1"
    if ! cd "$dir" 2>/dev/null; then
        error_exit "Cannot change to directory: $dir"
    fi
}

# Get absolute path
abs_path() {
    local path="$1"
    if [[ -d "$path" ]]; then
        (cd "$path" && pwd)
    elif [[ -f "$path" ]]; then
        local dir_path
        local file_name
        dir_path=$(cd "$(dirname "$path")" && pwd)
        file_name=$(basename "$path")
        echo "${dir_path}/${file_name}"
    else
        echo "$path"
    fi
}

# Load configuration
load_config() {
    local config_file="${1:-scripts/config/deploy.conf}"
    if [[ -f "$config_file" ]]; then
        # shellcheck source=/dev/null
        source "$config_file"
        log_debug "Configuration loaded from $config_file"
    else
        log_warning "Configuration file not found: $config_file, using defaults"
    fi
}

