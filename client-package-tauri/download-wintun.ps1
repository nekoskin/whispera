# Скрипт для автоматической загрузки wintun.dll

$ErrorActionPreference = "Stop"

$resourcesDir = Join-Path $PSScriptRoot "src-tauri\resources"
$dllPath = Join-Path $resourcesDir "wintun.dll"

# Создаем директорию, если не существует
if (-not (Test-Path $resourcesDir)) {
    New-Item -ItemType Directory -Path $resourcesDir -Force | Out-Null
}

# Проверяем, существует ли уже wintun.dll
if (Test-Path $dllPath) {
    $fileSize = (Get-Item $dllPath).Length
    if ($fileSize -gt 0) {
        Write-Host "wintun.dll already exists at: $dllPath" -ForegroundColor Green
        Write-Host "   File size: $fileSize bytes" -ForegroundColor Gray
        exit 0
    }
}

# Проверяем альтернативные места, где может быть wintun.dll
$alternativePaths = @()

# Определяем архитектуру для поиска
$searchArch = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $searchArch = "x86"
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $searchArch = "arm64"
}

# Проверяем папку wintun в resources (если распакован архив)
$wintunDir = Join-Path $PSScriptRoot "src-tauri\resources\wintun"
if (Test-Path $wintunDir) {
    $wintunDllInArchive = Join-Path $wintunDir "bin\$searchArch\wintun.dll"
    if (Test-Path $wintunDllInArchive) {
        $alternativePaths += $wintunDllInArchive
    }
    # Также пробуем amd64 для x64 систем
    if ($searchArch -ne "amd64") {
        $wintunDllAmd64 = Join-Path $wintunDir "bin\amd64\wintun.dll"
        if (Test-Path $wintunDllAmd64) {
            $alternativePaths += $wintunDllAmd64
        }
    }
}

# Добавляем стандартные пути
$alternativePaths += @(
    "$env:ProgramFiles\WireGuard\wintun.dll",
    "${env:ProgramFiles(x86)}\WireGuard\wintun.dll",
    "$env:LOCALAPPDATA\Programs\WireGuard\wintun.dll",
    "$env:USERPROFILE\Downloads\wintun.dll",
    "$env:USERPROFILE\Downloads\wintun-x64.dll"
)

foreach ($altPath in $alternativePaths) {
    if (Test-Path $altPath) {
        $fileSize = (Get-Item $altPath).Length
        if ($fileSize -gt 0) {
            Write-Host "Found wintun.dll at: $altPath" -ForegroundColor Cyan
            Write-Host "Copying to resources..." -ForegroundColor Yellow
            Copy-Item $altPath $dllPath -Force
            Write-Host "✅ wintun.dll copied successfully to: $dllPath" -ForegroundColor Green
            exit 0
        }
    }
}

Write-Host "Downloading wintun.dll..." -ForegroundColor Yellow

# Определяем архитектуру
$arch = "x64"
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    $arch = "x64"
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $arch = "x86"
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $arch = "arm64"
}

# Пробуем несколько версий и URL
$versions = @("v0.14.1", "v0.15", "v0.14", "latest")
$baseUrls = @(
    "https://github.com/WireGuard/wintun/releases/download",
    "https://build.wireguard.com/distros/wintun"
)

$url = $null
$dllFileName = "wintun-$arch.dll"

# Пробуем найти рабочий URL
foreach ($baseUrl in $baseUrls) {
    foreach ($version in $versions) {
        if ($baseUrl -like "*github*") {
            $testUrl = "$baseUrl/$version/$dllFileName"
        } else {
            $testUrl = "$baseUrl/$dllFileName"
        }
        
        # Пробуем HEAD запрос для проверки доступности
        try {
            $ProgressPreference = 'SilentlyContinue'
            $response = Invoke-WebRequest -Uri $testUrl -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                $url = $testUrl
                Write-Host "Found working URL: $url" -ForegroundColor Green
                break
            }
        } catch {
            # Продолжаем поиск
        }
        $ProgressPreference = 'Continue'
    }
    if ($url) { break }
}

# Если не нашли, используем последнюю известную версию
if (-not $url) {
    $url = "https://github.com/WireGuard/wintun/releases/latest/download/$dllFileName"
    Write-Host "Using latest release URL: $url" -ForegroundColor Yellow
}

# Функция загрузки через WebClient (более надежный метод)
function Download-WithWebClient {
    param([string]$Url, [string]$OutFile)
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
        $webClient.DownloadFile($Url, $OutFile)
        $webClient.Dispose()
        return $true
    } catch {
        return $false
    }
}

# Функция загрузки через Invoke-WebRequest
function Download-WithInvokeWebRequest {
    param([string]$Url, [string]$OutFile)
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop -TimeoutSec 30
        $ProgressPreference = 'Continue'
        return $true
    } catch {
        $ProgressPreference = 'Continue'
        return $false
    }
}

Write-Host "Attempting to download wintun.dll..." -ForegroundColor Yellow

# Настраиваем TLS и SSL
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$downloadSuccess = $false
$maxRetries = 3

# Метод 1: Пробуем через WebClient (более надежный)
for ($i = 1; $i -le $maxRetries; $i++) {
    Write-Host "Attempt ${i}/${maxRetries}: Trying WebClient method..." -ForegroundColor Cyan
    if (Download-WithWebClient -Url $url -OutFile $dllPath) {
        $downloadSuccess = $true
        break
    }
    if ($i -lt $maxRetries) {
        Start-Sleep -Seconds 2
    }
}

# Метод 2: Если WebClient не сработал, пробуем Invoke-WebRequest
if (-not $downloadSuccess) {
    for ($i = 1; $i -le $maxRetries; $i++) {
        Write-Host "Attempt ${i}/${maxRetries}: Trying Invoke-WebRequest method..." -ForegroundColor Cyan
        if (Download-WithInvokeWebRequest -Url $url -OutFile $dllPath) {
            $downloadSuccess = $true
            break
        }
        if ($i -lt $maxRetries) {
            Start-Sleep -Seconds 2
        }
    }
}

# Метод 3: Пробуем через curl (если доступен)
if (-not $downloadSuccess) {
    $curlPath = Get-Command curl -ErrorAction SilentlyContinue
    if ($curlPath) {
        Write-Host "Attempting curl method..." -ForegroundColor Cyan
        try {
            & curl -L -o $dllPath $url
            if (Test-Path $dllPath) {
                $downloadSuccess = $true
            }
        } catch {
            # Ignore
        }
    }
}

if ($downloadSuccess -and (Test-Path $dllPath)) {
    $fileSize = (Get-Item $dllPath).Length
    if ($fileSize -gt 0) {
        Write-Host "✅ wintun.dll downloaded successfully to: $dllPath" -ForegroundColor Green
        Write-Host "   File size: $fileSize bytes" -ForegroundColor Gray
        exit 0
    } else {
        Remove-Item $dllPath -Force -ErrorAction SilentlyContinue
        $downloadSuccess = $false
    }
}

if (-not $downloadSuccess) {
    Write-Host "" -ForegroundColor Red
    Write-Host "Failed to download wintun.dll after multiple attempts" -ForegroundColor Red
    Write-Host "" -ForegroundColor Yellow
    Write-Host "wintun.dll is required for build!" -ForegroundColor Red
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Please download manually using one of these methods:" -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Method 1 - Official site (Recommended):" -ForegroundColor Cyan
    Write-Host "  1. Open: https://www.wintun.net/" -ForegroundColor White
    Write-Host "  2. Download wintun-x64.dll" -ForegroundColor White
    Write-Host "  3. Save as: $dllPath" -ForegroundColor White
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Method 2 - GitHub releases:" -ForegroundColor Cyan
    Write-Host "  1. Open: https://github.com/WireGuard/wintun/releases" -ForegroundColor White
    Write-Host "  2. Download latest wintun-x64.dll" -ForegroundColor White
    Write-Host "  3. Save as: $dllPath" -ForegroundColor White
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Method 3 - If WireGuard is installed:" -ForegroundColor Cyan
    Write-Host "  Copy from: $env:ProgramFiles\WireGuard\wintun.dll" -ForegroundColor White
    Write-Host "  To: $dllPath" -ForegroundColor White
    Write-Host "" -ForegroundColor Yellow
    Write-Host "After downloading, run the script again or place the file manually." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    
    # Пробуем открыть браузер с официальным сайтом
    try {
        Start-Process "https://www.wintun.net/"
    } catch {
        # Ignore
    }
    
    exit 1
}

