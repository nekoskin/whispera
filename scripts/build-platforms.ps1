# Build for all platforms
# Usage: .\scripts\build-platforms.ps1

$ErrorActionPreference = "Stop"
$Version = "1.0.0"
$BuildDir = Join-Path $PSScriptRoot "..\bin"
$LDFlags = "-s -w -X main.Version=$Version"

# Platforms to build
$Platforms = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Ext = "" }
)

# Binaries to build
$Binaries = @(
    @{ Name = "client"; Path = "./cmd/client" },
    @{ Name = "server"; Path = "./cmd/server" },
    @{ Name = "keygen"; Path = "./cmd/keygen" }
)

Write-Host "Building Whispera v$Version for all platforms..." -ForegroundColor Cyan

foreach ($platform in $Platforms) {
    $os = $platform.GOOS
    $arch = $platform.GOARCH
    $ext = $platform.Ext
    
    $outputDir = Join-Path $BuildDir "$os-$arch"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }
    
    Write-Host "`n[$os/$arch]" -ForegroundColor Yellow
    
    foreach ($binary in $Binaries) {
        $name = $binary.Name
        $path = $binary.Path
        $output = Join-Path $outputDir "$name$ext"
        
        Write-Host "  Building $name..." -ForegroundColor Gray
        
        $env:GOOS = $os
        $env:GOARCH = $arch
        $env:CGO_ENABLED = "0"
        
        go build -ldflags $LDFlags -o $output $path
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    OK: $output" -ForegroundColor Green
        } else {
            Write-Host "    FAILED: $name" -ForegroundColor Red
        }
    }
}

# Reset environment
$env:GOOS = ""
$env:GOARCH = ""
$env:CGO_ENABLED = ""

Write-Host "`nBuild complete! Binaries in $BuildDir" -ForegroundColor Cyan

# List all built files
Write-Host "`nBuilt files:" -ForegroundColor Yellow
Get-ChildItem -Recurse $BuildDir -File | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 2)
    Write-Host "  $($_.FullName.Replace($BuildDir, ''))  ($size MB)" -ForegroundColor Gray
}
