# Whispera - Main Build Script
# Usage: .\run.ps1 [command]
# Commands: build, test, clean, server, client, all

param(
    [Parameter(Position=0)]
    [ValidateSet("build", "test", "clean", "server", "client", "all", "help", "dev", "lint")]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"
$ScriptsDir = Join-Path $PSScriptRoot "scripts"

function Show-Help {
    Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║                    WHISPERA BUILD SYSTEM                      ║
╠═══════════════════════════════════════════════════════════════╣
║  Usage: .\run.ps1 <command>                                   ║
║                                                                ║
║  Commands:                                                     ║
║    build    - Build all binaries (client, server, keygen)    ║
║    server   - Build and run server                            ║
║    client   - Build and run client                            ║
║    test     - Run all tests                                   ║
║    lint     - Run linters                                     ║
║    clean    - Clean build artifacts                           ║
║    dev      - Start development mode                          ║
║    all      - Build for all platforms                         ║
║    help     - Show this help                                  ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Build-All {
    Write-Host "Building Whispera..." -ForegroundColor Green
    
    Write-Host "  [1/4] Building client..." -ForegroundColor Yellow
    go build -o bin/client.exe ./cmd/client
    
    Write-Host "  [2/4] Building server..." -ForegroundColor Yellow
    go build -o bin/server.exe ./cmd/server
    
    Write-Host "  [3/4] Building keygen..." -ForegroundColor Yellow
    go build -o bin/keygen.exe ./cmd/keygen
    
    Write-Host "  [4/4] Building speedtest..." -ForegroundColor Yellow
    go build -o bin/speedtest-server.exe ./cmd/whispera-speedtest-server
    
    Write-Host "Build complete! Binaries in ./bin/" -ForegroundColor Green
}

function Run-Server {
    Write-Host "Building server..." -ForegroundColor Yellow
    go build -o bin/server.exe ./cmd/server
    
    Write-Host "Starting server..." -ForegroundColor Green
    & ./bin/server.exe -config config.yaml
}

function Run-Client {
    Write-Host "Building client..." -ForegroundColor Yellow
    go build -o bin/client.exe ./cmd/client
    
    Write-Host "Starting client..." -ForegroundColor Green
    & ./bin/client.exe -config client_config.yaml
}

function Run-Tests {
    Write-Host "Running tests..." -ForegroundColor Green
    go test -v ./...
}

function Run-Lint {
    Write-Host "Running linters..." -ForegroundColor Green
    go vet ./...
    Write-Host "  go vet passed" -ForegroundColor Green
    
    if (Get-Command golangci-lint -ErrorAction SilentlyContinue) {
        golangci-lint run --timeout=5m
        Write-Host "  golangci-lint passed" -ForegroundColor Green
    } else {
        Write-Host "  golangci-lint not installed, skipping" -ForegroundColor Yellow
    }
}

function Clean-Build {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    
    if (Test-Path "bin") {
        Remove-Item -Recurse -Force "bin"
    }
    
    Remove-Item -Force "*.exe" -ErrorAction SilentlyContinue
    Remove-Item -Force "coverage.*" -ErrorAction SilentlyContinue
    
    go clean -cache
    Write-Host "Clean complete!" -ForegroundColor Green
}

function Build-AllPlatforms {
    Write-Host "Building for all platforms..." -ForegroundColor Green
    & "$ScriptsDir\build-platforms.ps1"
}

function Start-DevMode {
    Write-Host "Starting development mode..." -ForegroundColor Green
    Write-Host "  Watching for changes..." -ForegroundColor Yellow
    
    # Build once
    Build-All
    
    Write-Host "  Development server ready!" -ForegroundColor Green
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor Yellow
    
    Run-Server
}

# Create bin directory if not exists
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# Execute command
switch ($Command) {
    "build"  { Build-All }
    "server" { Run-Server }
    "client" { Run-Client }
    "test"   { Run-Tests }
    "lint"   { Run-Lint }
    "clean"  { Clean-Build }
    "all"    { Build-AllPlatforms }
    "dev"    { Start-DevMode }
    "help"   { Show-Help }
    default  { Show-Help }
}
