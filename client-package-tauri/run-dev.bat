@echo off
setlocal enabledelayedexpansion
:: ============================================================
:: Проверка прав администратора (нужны для TUN и netsh/route)
:: Если скрипт запущен без прав, перезапускаем себя с UAC
:: ============================================================
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo [INFO] Требуются права администратора для настройки TUN и маршрутов
    echo [INFO] Запрос прав через UAC...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

chcp 65001 >nul
echo ========================================
echo Whispera Client - Development Mode
echo ========================================
echo.

cd /d "%~dp0"

:: ========================================
:: Whispera TUN auto-setup (MTU / IP / routes / firewall)
:: ========================================
:: use caret outside of quotes so batch continues lines; each segment starts and ends with "
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$if = Get-NetAdapter | Where-Object InterfaceDescription -Like '*Whispera*' | Sort-Object ifIndex | Select-Object -First 1; if(-not $if){exit};" ^
  "Set-NetIPInterface -InterfaceIndex $if.ifIndex -NlMtuBytes 1280;" ^
  "if(-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress 198.18.0.1 -ErrorAction SilentlyContinue)){ New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress 198.18.0.1 -PrefixLength 30 -DefaultGateway 198.18.0.2 };" ^
  "if(-not (Get-NetRoute -InterfaceIndex $if.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)){ New-NetRoute -InterfaceIndex $if.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop 198.18.0.2 -RouteMetric 15 };" ^
  "$srv='193.233.254.130'; if(-not (Get-NetRoute -DestinationPrefix ($srv+'/32') -ErrorAction SilentlyContinue)){ $gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '198.18.0.2' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop; if($gw){ New-NetRoute -DestinationPrefix ($srv+'/32') -NextHop $gw -RouteMetric 10 } else { Write-Warning 'Whispera: default IPv4 gateway not found, host-route not added' } };" ^
  "$prof = Get-NetConnectionProfile | Where-Object InterfaceAlias -Like '*Whispera*'; if($prof -and $prof.NetworkCategory -eq 'Public'){ Set-NetConnectionProfile -InterfaceAlias $prof.InterfaceAlias -NetworkCategory Private };" ^
  "foreach($rule in @('Whispera UDP','Whispera TCP','Whispera ICMP')){ if(-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)){ switch($rule){ 'Whispera UDP'  { New-NetFirewallRule -DisplayName $rule -InterfaceAlias $if.Name -Direction Inbound -Action Allow -Protocol UDP  } 'Whispera TCP'  { New-NetFirewallRule -DisplayName $rule -InterfaceAlias $if.Name -Direction Inbound -Action Allow -Protocol TCP  } 'Whispera ICMP' { New-NetFirewallRule -DisplayName $rule -InterfaceAlias $if.Name -Direction Inbound -Action Allow -Protocol ICMPv4 } } } }"

set GO_BIN_NAME=whispera-go-client-x86_64-pc-windows-msvc.exe

:: Проверяем наличие wintun.dll в resources
if not exist "src-tauri\resources\wintun.dll" (
    echo [INFO] Загрузка wintun.dll...
    powershell -ExecutionPolicy Bypass -File "download-wintun.ps1" >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] Не удалось загрузить wintun.dll
        pause
        exit /b 1
    )
    if not exist "src-tauri\resources\wintun.dll" (
        echo [ERROR] wintun.dll не найден после загрузки
        pause
        exit /b 1
    )
)

:: Проверяем наличие Go
where go >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Go компилятор не найден
    pause
    exit /b 1
)

:: Обновляем Go зависимости
pushd "%~dp0\.."
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Не удалось перейти в корневую директорию
    pause
    exit /b 1
)
go mod tidy >nul 2>&1

:: Проверяем наличие Go клиента в resources
echo [INFO] Сборка Go клиента с gvisor...

if exist "cmd\client\main.go" (
    :: Создаем выходную директорию, если её нет
    if not exist "client-package-tauri\src-tauri\resources" (
        mkdir "client-package-tauri\src-tauri\resources" >nul 2>&1
    )
    
    :: Компилируем с тегом with_gvisor для поддержки gvisor tunstack
    go build -tags=with_gvisor -o client-package-tauri\src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe .\cmd\client
    if errorlevel 1 (
        echo [ERROR] Ошибка сборки Go клиента
        popd
        pause
        exit /b 1
    )
    :: Создаем копию с базовым именем для Tauri sidecar
    :: Tauri ищет файл: whispera-go-client-{target_triple} в resources или корне src-tauri
    :: На Windows: whispera-go-client-x86_64-pc-windows-msvc.exe
    if exist client-package-tauri\src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe (
        :: Файл уже имеет правильное имя для Tauri externalBin
        :: Также создаем копию с базовым именем для обратной совместимости
        copy /Y client-package-tauri\src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe client-package-tauri\src-tauri\resources\whispera-go-client.exe >nul
        :: Копируем в корень src-tauri для сборки (Tauri может искать там)
        copy /Y client-package-tauri\src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe client-package-tauri\src-tauri\whispera-go-client-x86_64-pc-windows-msvc.exe >nul
    ) else (
        echo [ERROR] Файл не создан после сборки
        popd
        pause
        exit /b 1
    )
    popd
) else (
    echo [ERROR] Не найден cmd\client\main.go
    popd
    pause
    exit /b 1
)

:: Создаем директорию bin для sidecar и копируем туда бинарник с правильным именем
if exist "src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe" (
    if not exist "src-tauri\bin" mkdir "src-tauri\bin"
    :: Останавливаем все процессы whispera-go-client, которые могут блокировать файлы
    taskkill /F /IM whispera-go-client.exe >nul 2>&1
    if exist "%SystemRoot%\System32\timeout.exe" (
        timeout /t 1 /nobreak >nul 2>&1
    ) else (
        powershell -Command "Start-Sleep -Milliseconds 1000" >nul 2>&1
    )
    :: Удаляем старый файл, если он существует и заблокирован
    if exist "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" (
        del /F /Q "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" >nul 2>&1
        :: Небольшая задержка для освобождения файла
        if exist "%SystemRoot%\System32\timeout.exe" (
            timeout /t 1 /nobreak >nul 2>&1
        ) else (
            :: Fallback: используем PowerShell для задержки
            powershell -Command "Start-Sleep -Milliseconds 500" >nul 2>&1
        )
    )
    copy /Y "src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe" "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" >nul
    
    :: Также копируем бинарник в AppData перед запуском
    if not exist "%APPDATA%\com.whispera.client" (
        mkdir "%APPDATA%\com.whispera.client" >nul 2>&1
    )
    if exist "src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe" (
        copy /Y "src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe" "%APPDATA%\com.whispera.client\whispera-go-client-x86_64-pc-windows-msvc.exe" >nul
        copy /Y "src-tauri\resources\whispera-go-client-x86_64-pc-windows-msvc.exe" "%APPDATA%\com.whispera.client\whispera-go-client.exe" >nul
    )
    
    :: Копируем wintun.dll в AppData
    if exist "src-tauri\resources\wintun.dll" (
        copy /Y "src-tauri\resources\wintun.dll" "%APPDATA%\com.whispera.client\wintun.dll" >nul
    ) else if exist "src-tauri\resources\wintun\bin\amd64\wintun.dll" (
        copy /Y "src-tauri\resources\wintun\bin\amd64\wintun.dll" "%APPDATA%\com.whispera.client\wintun.dll" >nul
    )
)

:: Небольшая задержка, чтобы убедиться, что файл не заблокирован
if exist "%SystemRoot%\System32\timeout.exe" (
    timeout /t 1 /nobreak >nul 2>&1
) else (
    :: Fallback: используем PowerShell для задержки
    powershell -Command "Start-Sleep -Milliseconds 1000" >nul 2>&1
)

:: Проверяем, что файл доступен для чтения
if not exist "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" (
    echo [ERROR] Файл whispera-go-client-x86_64-pc-windows-msvc.exe не найден в bin
    pause
    exit /b 1
)

:: Финальная проверка - убеждаемся, что файл существует перед запуском Tauri
if not exist "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" (
    echo [ERROR] Файл не найден
    pause
    exit /b 1
)

:: Устанавливаем атрибуты файла (убираем read-only, если есть)
attrib -R "src-tauri\bin\whispera-go-client-x86_64-pc-windows-msvc.exe" >nul 2>&1

:: Проверяем наличие npm
where npm >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] npm не найден в PATH
    pause
    exit /b 1
)

:: Проверяем и устанавливаем npm зависимости
if not exist "node_modules" (
    echo [INFO] Установка npm зависимостей...
    call npm install
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] Не удалось установить npm зависимости
        pause
        exit /b 1
    )
)

npm run tauri dev

pause

