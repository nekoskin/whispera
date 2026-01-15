# Check routing configuration for Whispera VPN tunnel
# This script verifies that routes are correctly set up for:
# 1. VPN server IP -> physical gateway (prevent routing loop)
# 2. All traffic (0.0.0.0/1 and 128.0.0.0/1) -> TUN interface

param(
    [string]$VPNServerIP = $env:WHISPERA_VPN_SERVER,
    [string]$TunIP = "10.0.85.1",
    [string]$TunName = "Whispera"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Whispera Route Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get current route table
Write-Host "Retrieving route table..." -ForegroundColor Yellow
$routes = route print

Write-Host ""
Write-Host "1. VPN SERVER ROUTE CHECK" -ForegroundColor Green
Write-Host "-" * 40

if ($VPNServerIP) {
    Write-Host "Looking for VPN server route: $VPNServerIP"
    if ($routes -match [regex]::Escape($VPNServerIP)) {
        Write-Host "✓ VPN server route FOUND" -ForegroundColor Green
        # Extract and show the route
        $vpnLines = $routes | Select-String $VPNServerIP
        foreach ($line in $vpnLines) {
            Write-Host "  $line" -ForegroundColor Green
        }
    } else {
        Write-Host "✗ VPN server route NOT FOUND" -ForegroundColor Red
        Write-Host "  Expected to find route for: $VPNServerIP"
    }
} else {
    Write-Host "⚠ VPN server IP not provided" -ForegroundColor Yellow
    Write-Host "  Set env variable: WHISPERA_VPN_SERVER=<IP>" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "2. TUN INTERFACE ROUTES CHECK" -ForegroundColor Green
Write-Host "-" * 40

Write-Host "Looking for TUN routes (0.0.0.0/1 and 128.0.0.0/1)..."
$tun0Found = $false
$tun128Found = $false

if ($routes -match "0\.0\.0\.0.*128\.0\.0\.0") {
    Write-Host "✓ TUN route 0.0.0.0/1 FOUND" -ForegroundColor Green
    $tunLines = $routes | Select-String "0\.0\.0\.0.*128\.0\.0\.0"
    foreach ($line in $tunLines) {
        Write-Host "  $line" -ForegroundColor Green
    }
    $tun0Found = $true
} else {
    Write-Host "✗ TUN route 0.0.0.0/1 NOT FOUND" -ForegroundColor Red
}

if ($routes -match "128\.0\.0\.0.*128\.0\.0\.0") {
    Write-Host "✓ TUN route 128.0.0.0/1 FOUND" -ForegroundColor Green
    $tunLines = $routes | Select-String "128\.0\.0\.0.*128\.0\.0\.0"
    foreach ($line in $tunLines) {
        Write-Host "  $line" -ForegroundColor Green
    }
    $tun128Found = $true
} else {
    Write-Host "✗ TUN route 128.0.0.0/1 NOT FOUND" -ForegroundColor Red
}

Write-Host ""
Write-Host "3. TUN INTERFACE CHECK" -ForegroundColor Green
Write-Host "-" * 40

$tunInterface = Get-NetAdapter -Name $TunName -ErrorAction SilentlyContinue
if ($tunInterface) {
    Write-Host "✓ TUN interface '$TunName' FOUND" -ForegroundColor Green
    Write-Host "  Status: $($tunInterface.Status)"
    Write-Host "  MAC: $($tunInterface.MacAddress)"
} else {
    Write-Host "✗ TUN interface '$TunName' NOT FOUND" -ForegroundColor Red
}

# Check TUN IP address
$tunAddress = Get-NetIPAddress -InterfaceAlias $TunName -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($tunAddress) {
    Write-Host "✓ TUN interface IP: $($tunAddress.IPAddress)" -ForegroundColor Green
} else {
    Write-Host "✗ No IPv4 address assigned to TUN interface" -ForegroundColor Red
}

Write-Host ""
Write-Host "4. SUMMARY" -ForegroundColor Green
Write-Host "-" * 40

$issues = @()
if (-not $VPNServerIP) {
    $issues += "VPN server IP not set"
}
if (-not $tun0Found) {
    $issues += "TUN route 0.0.0.0/1 missing"
}
if (-not $tun128Found) {
    $issues += "TUN route 128.0.0.0/1 missing"
}
if (-not $tunInterface) {
    $issues += "TUN interface not found"
}

if ($issues.Count -eq 0) {
    Write-Host "✓ All checks PASSED!" -ForegroundColor Green
    Write-Host "Routes are configured correctly for VPN tunnel" -ForegroundColor Green
} else {
    Write-Host "✗ Issues found:" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  • $issue" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "1. Make sure WHISPERA_VPN_SERVER env variable is set" -ForegroundColor Yellow
    Write-Host "2. Check if hev-socks5-tunnel process is running" -ForegroundColor Yellow
    Write-Host "3. Check Windows firewall/antivirus isn't blocking route changes" -ForegroundColor Yellow
    Write-Host "4. Try running this script as Administrator" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "5. FULL ROUTE TABLE" -ForegroundColor Green
Write-Host "-" * 40
Write-Host $routes
