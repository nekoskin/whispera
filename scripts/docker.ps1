# Docker build and run
# Usage: .\scripts\docker.ps1 [build|run|push]

param(
    [Parameter(Position=0)]
    [ValidateSet("build", "run", "push", "compose")]
    [string]$Command = "build"
)

$ErrorActionPreference = "Stop"
$ImageName = "whispera/server"
$Version = "latest"

function Docker-Build {
    Write-Host "Building Docker image..." -ForegroundColor Cyan
    docker build -t "${ImageName}:${Version}" .
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Image built: ${ImageName}:${Version}" -ForegroundColor Green
    } else {
        Write-Host "Docker build failed!" -ForegroundColor Red
        exit 1
    }
}

function Docker-Run {
    Write-Host "Running Docker container..." -ForegroundColor Cyan
    docker run -d `
        --name whispera-server `
        -p 51820:51820/udp `
        -p 443:443 `
        -v "${PWD}/config.yaml:/app/config.yaml" `
        "${ImageName}:${Version}"
    
    Write-Host "Container started: whispera-server" -ForegroundColor Green
    Write-Host "  UDP: 51820" -ForegroundColor Gray
    Write-Host "  HTTPS: 443" -ForegroundColor Gray
}

function Docker-Push {
    param([string]$Registry = "docker.io")
    
    Write-Host "Pushing to $Registry..." -ForegroundColor Cyan
    docker tag "${ImageName}:${Version}" "${Registry}/${ImageName}:${Version}"
    docker push "${Registry}/${ImageName}:${Version}"
    Write-Host "Pushed: ${Registry}/${ImageName}:${Version}" -ForegroundColor Green
}

function Docker-Compose {
    Write-Host "Starting with docker-compose..." -ForegroundColor Cyan
    docker-compose up -d
    Write-Host "Services started!" -ForegroundColor Green
    docker-compose ps
}

switch ($Command) {
    "build"   { Docker-Build }
    "run"     { Docker-Run }
    "push"    { Docker-Push }
    "compose" { Docker-Compose }
}
