# Build Whispera Sidecar (Pure Go for Tauri)
# Usage: ./build_sidecar.ps1

$ErrorActionPreference = "Stop"

$TARGET_DIR = "binaries"
# Tauri requires specific naming for sidecars: <command>-<target-triple>.exe
# Assuming x86_64 Windows
$BINARY_NAME = "whispera-sidecar-x86_64-pc-windows-msvc.exe"

Write-Host "🚧 Building Whispera Sidecar (No CGO)..." -ForegroundColor Cyan

# 1. Create directory
if (!(Test-Path $TARGET_DIR)) {
    New-Item -ItemType Directory -Path $TARGET_DIR | Out-Null
}

# 2. Build
# CGO_ENABLED=0 ensures pure Go build (no GCC needed)
$env:CGO_ENABLED = "0"
go build -trimpath -tags with_gvisor -ldflags "-s -w" -o "$TARGET_DIR/$BINARY_NAME" ./cmd/sidecar

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Success! Sidecar created at: $TARGET_DIR/$BINARY_NAME" -ForegroundColor Green
    Write-Host ""
    Write-Host "Integration Instructions:"
    Write-Host "1. Copy '$TARGET_DIR' folder to 'src-tauri/'"
    Write-Host "2. In tauri.conf.json:"
    Write-Host '   "bundle": { "externalBin": ["binaries/whispera-sidecar"] }'
    Write-Host "3. Call from JS:"
    Write-Host "   Command.sidecar('binaries/whispera-sidecar', ['-server', 'ip:port', ...])"
    Write-Host ""
    Write-Host "⚠️  APP MUST RUN AS ADMIN for TUN/Routing to work!" -ForegroundColor Yellow
} else {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}
