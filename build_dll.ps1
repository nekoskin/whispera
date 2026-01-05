# Build Whispera Client as DLL (Shared Library)
# Usage: ./build_dll.ps1

$ErrorActionPreference = "Stop"

$TARGET_DIR = "binaries"
$DLL_NAME = "whispera.dll"

Write-Host "🚧 Building Whispera DLL..." -ForegroundColor Cyan

# 1. Create directory
if (!(Test-Path $TARGET_DIR)) {
    New-Item -ItemType Directory -Path $TARGET_DIR | Out-Null
}

# 2. Build
# -buildmode=c-shared creates a DLL and a Header file
go build -buildmode=c-shared -trimpath -ldflags "-s -w" -o "$TARGET_DIR/$DLL_NAME" ./cmd/client_lib

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Success! DLL created at: $TARGET_DIR/$DLL_NAME" -ForegroundColor Green
    Write-Host ""
    Write-Host "Integration Instructions:"
    Write-Host "1. Copy '$TARGET_DIR/$DLL_NAME' to your app directory."
    Write-Host "2. Ensure 'wintun.dll' is also in that directory."
    Write-Host "3. Call 'StartConnection(server, transport, key)' from your app."
} else {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}
