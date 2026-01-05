# Deploy server to remote host
# Usage: .\scripts\deploy.ps1 -Host <hostname> -User <user>

param(
    [Parameter(Mandatory=$true)]
    [string]$RemoteHost,
    
    [Parameter(Mandatory=$true)]
    [string]$User,
    
    [string]$Port = "22",
    [string]$RemotePath = "/opt/whispera"
)

$ErrorActionPreference = "Stop"

Write-Host "Deploying Whispera to $User@$RemoteHost..." -ForegroundColor Cyan

# Build Linux binary
Write-Host "`n[1/4] Building Linux binary..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

go build -ldflags "-s -w" -o bin/server-linux ./cmd/server
$env:GOOS = ""
$env:GOARCH = ""

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "  Build complete!" -ForegroundColor Green

# Upload binary
Write-Host "`n[2/4] Uploading binary..." -ForegroundColor Yellow
scp -P $Port bin/server-linux "${User}@${RemoteHost}:${RemotePath}/server"

# Upload config
Write-Host "`n[3/4] Uploading config..." -ForegroundColor Yellow
scp -P $Port config.yaml "${User}@${RemoteHost}:${RemotePath}/config.yaml"

# Restart service
Write-Host "`n[4/4] Restarting service..." -ForegroundColor Yellow
ssh -p $Port "${User}@${RemoteHost}" "sudo systemctl restart whispera"

Write-Host "`nDeployment complete!" -ForegroundColor Green
Write-Host "Server running at $RemoteHost" -ForegroundColor Gray
