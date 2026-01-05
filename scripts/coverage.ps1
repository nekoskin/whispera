# Run tests with coverage
# Usage: .\scripts\coverage.ps1

$ErrorActionPreference = "Stop"

Write-Host "Running tests with coverage..." -ForegroundColor Cyan

# Run tests
go test -v -coverprofile=coverage.out ./...

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nGenerating coverage report..." -ForegroundColor Yellow
    go tool cover -html=coverage.out -o coverage.html
    
    # Calculate coverage percentage
    $coverage = go tool cover -func=coverage.out | Select-String "total:" | ForEach-Object {
        $_ -match "(\d+\.\d+)%" | Out-Null
        $Matches[1]
    }
    
    Write-Host "`nCoverage: $coverage%" -ForegroundColor Green
    Write-Host "Report: coverage.html" -ForegroundColor Gray
    
    # Open in browser
    Start-Process coverage.html
} else {
    Write-Host "Tests failed!" -ForegroundColor Red
    exit 1
}
