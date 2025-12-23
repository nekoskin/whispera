@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo Whispera Tauri - Cross-Platform Build
echo ========================================
echo.

:: Check dependencies
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust/Cargo не найден
    echo Установите Rust: https://rustup.rs/
    pause
    exit /b 1
)
echo [OK] Rust найден
cargo --version
echo.

where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js не найден
    echo Установите Node.js: https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js найден
node --version
npm --version
echo.

where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Go не найден - пропустим сборку Go клиента
    set SKIP_GO=1
) else (
    echo [OK] Go найден
    go version
    echo.
)

:: Go to script directory
cd /d "%~dp0"

:: Install dependencies
if not exist "node_modules" (
    echo [INFO] Установка npm зависимостей...
    npm install
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Ошибка установки зависимостей
        pause
        exit /b 1
    )
)

:: Download wintun.dll
if not exist "src-tauri\resources\wintun.dll" (
    echo [INFO] Загрузка wintun.dll...
    powershell -ExecutionPolicy Bypass -File "download-wintun.ps1"
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Не удалось загрузить wintun.dll автоматически
    )
)

:: Build Go client for Windows
if not defined SKIP_GO (
    if not exist "src-tauri\resources\whispera-go-client.exe" (
        echo [INFO] Сборка Go клиента для Windows...
        cd /d "%~dp0\.."
        set GOOS=windows
        set GOARCH=amd64
        go build -ldflags="-s -w" -o client-package-tauri\src-tauri\resources\whispera-go-client.exe .\cmd\client
        if %ERRORLEVEL% NEQ 0 (
            echo [ERROR] Ошибка сборки Go клиента
            pause
            exit /b 1
        )
        cd /d "%~dp0"
        echo [SUCCESS] Go клиент для Windows собран
        echo.
    )
)

:: Install Rust targets
echo [INFO] Установка Rust targets для кроссплатформенной сборки...
rustup target add x86_64-pc-windows-msvc >nul 2>&1
rustup target add x86_64-unknown-linux-gnu >nul 2>&1
rustup target add x86_64-apple-darwin >nul 2>&1
rustup target add aarch64-apple-darwin >nul 2>&1

:: Create output directory
set OUTPUT_DIR=..\releases
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

:: Menu
echo.
echo Выберите платформы для сборки:
echo 1. Windows (x86_64)
echo 2. Linux (x86_64)
echo 3. macOS (x86_64)
echo 4. macOS (ARM64)
echo 5. Все платформы
echo.
set /p CHOICE="Введите номер (1-5) или нажмите Enter для всех: "
if "%CHOICE%"=="" set CHOICE=5

if "%CHOICE%"=="1" (
    call :build_platform "x86_64-pc-windows-msvc" "windows"
) else if "%CHOICE%"=="2" (
    call :build_platform "x86_64-unknown-linux-gnu" "linux"
) else if "%CHOICE%"=="3" (
    call :build_platform "x86_64-apple-darwin" "macos"
) else if "%CHOICE%"=="4" (
    call :build_platform "aarch64-apple-darwin" "macos-arm"
) else if "%CHOICE%"=="5" (
    call :build_platform "x86_64-pc-windows-msvc" "windows"
    call :build_platform "x86_64-unknown-linux-gnu" "linux"
    call :build_platform "x86_64-apple-darwin" "macos"
    call :build_platform "aarch64-apple-darwin" "macos-arm"
) else (
    echo [ERROR] Неверный выбор
    pause
    exit /b 1
)

echo.
echo ========================================
echo Сборка завершена!
echo Результаты в: %OUTPUT_DIR%
echo ========================================
pause
exit /b 0

:build_platform
set TARGET=%~1
set PLATFORM=%~2

echo.
echo ========================================
echo [INFO] Сборка для %PLATFORM% (%TARGET%)
echo ========================================

echo [INFO] Сборка Tauri приложения...
npm run tauri build -- --target %TARGET%
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Ошибка сборки для %PLATFORM%
    goto :eof
)

:: Copy results
set BUNDLE_DIR=src-tauri\target\%TARGET%\release\bundle
if exist "%BUNDLE_DIR%" (
    set PLATFORM_DIR=%OUTPUT_DIR%\%PLATFORM%
    if not exist "%PLATFORM_DIR%" mkdir "%PLATFORM_DIR%"
    
    xcopy /E /I /Y "%BUNDLE_DIR%\*" "%PLATFORM_DIR%\" >nul 2>&1
    
    echo [SUCCESS] %PLATFORM% инсталляторы созданы в: %PLATFORM_DIR%
    echo.
    echo Созданные файлы:
    dir /B "%PLATFORM_DIR%" 2>nul | findstr /R "\.msi$ \.exe$ \.AppImage$ \.deb$ \.dmg$ \.app$" >nul
    if %ERRORLEVEL% EQU 0 (
        dir /B "%PLATFORM_DIR%" 2>nul | findstr /R "\.msi$ \.exe$ \.AppImage$ \.deb$ \.dmg$ \.app$"
    )
)

goto :eof

