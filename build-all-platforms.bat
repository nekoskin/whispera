@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: Go to root directory
cd /d "%~dp0"
set ROOT_DIR=%CD%

echo ========================================
echo Whispera - Universal Build System
echo ========================================
echo.

:: Check dependencies
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Go не найден
    echo Установите Go: https://golang.org/dl/
    pause
    exit /b 1
)
echo [OK] Go найден
go version >nul 2>&1

where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Rust не найден - пропустим сборку Tauri
    set SKIP_TAURI=1
) else (
    echo [OK] Rust найден
    cargo --version >nul 2>&1
)

where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Node.js не найден - пропустим сборку Tauri
    set SKIP_TAURI=1
) else (
    echo [OK] Node.js найден
)

echo.
echo [INFO] Инициализация сборки...
echo.

:: Create output directory
set OUTPUT_DIR=releases
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OUTPUT_DIR%\go-binaries" mkdir "%OUTPUT_DIR%\go-binaries"

:: Check if choice was passed as argument
set "CHOICE=%~1"
if "!CHOICE!"=="" (
    :: Menu
    echo Выберите действие:
    echo 1. Собрать Go бинарники для всех платформ
    echo 2. Собрать Tauri клиент для всех платформ
    echo 3. Собрать всё (Go + Tauri)
    echo 4. Собрать только Windows (Go + Tauri)
    echo 5. Выход
    echo.
    set /p CHOICE="Введите номер (1-5): "
) else (
    echo [INFO] Выбрана опция: !CHOICE!
)
if "!CHOICE!"=="1" (
    echo [INFO] Запуск сборки Go бинарников
    call :build_go_binaries
) else if "!CHOICE!"=="2" (
    echo [INFO] Запуск сборки Tauri клиента
    call :build_tauri_client
) else if "!CHOICE!"=="3" (
    echo [INFO] Запуск сборки всего (Go + Tauri)
    call :build_go_binaries
    if !ERRORLEVEL! NEQ 0 (
        echo [WARNING] Ошибка при сборке Go бинарников, продолжаем
    )
    call :build_tauri_client
) else if "!CHOICE!"=="4" (
    echo [INFO] Запуск сборки только для Windows
    call :build_go_binaries_windows
    if !ERRORLEVEL! NEQ 0 (
        echo [WARNING] Ошибка при сборке Go бинарников, продолжаем
    )
    call :build_tauri_windows
) else if "!CHOICE!"=="5" (
    exit /b 0
) else if "!CHOICE!"=="" (
    echo [ERROR] Неверный выбор - CHOICE пуст
    pause
    exit /b 1
) else (
    echo [ERROR] Неверный выбор: "!CHOICE!"
    echo Использование: build-all-platforms.bat [1^|2^|3^|4^|5]
    echo   1 - Собрать Go бинарники
    echo   2 - Собрать Tauri клиент
    echo   3 - Собрать всё
    echo   4 - Собрать только Windows
    echo   5 - Выход
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

:build_go_binaries
echo.
echo [INFO] Сборка Go бинарников для всех платформ...
echo.

set PLATFORMS=windows/amd64 windows/386 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

for %%P in (%PLATFORMS%) do (
    for /f "tokens=1,2 delims=/" %%A in ("%%P") do (
        set GOOS=%%A
        set GOARCH=%%B
        
        echo [INFO] Сборка для !GOOS!/!GOARCH!...
        
        :: Build client
        set CLIENT_OUTPUT=%OUTPUT_DIR%\go-binaries\whispera-client-!GOOS!-!GOARCH!
        if "!GOOS!"=="windows" set CLIENT_OUTPUT=!CLIENT_OUTPUT!.exe
        
        set GOOS=!GOOS!
        set GOARCH=!GOARCH!
        go build -ldflags="-s -w" -o "!CLIENT_OUTPUT!" .\cmd\client
        if !ERRORLEVEL! EQU 0 (
            echo [SUCCESS] Клиент: !CLIENT_OUTPUT!
        ) else (
            echo [ERROR] Ошибка сборки клиента для !GOOS!/!GOARCH!
        )
        
        :: Build server
        set SERVER_OUTPUT=%OUTPUT_DIR%\go-binaries\whispera-server-!GOOS!-!GOARCH!
        if "!GOOS!"=="windows" set SERVER_OUTPUT=!SERVER_OUTPUT!.exe
        
        go build -ldflags="-s -w" -o "!SERVER_OUTPUT!" .\cmd\server
        if !ERRORLEVEL! EQU 0 (
            echo [SUCCESS] Сервер: !SERVER_OUTPUT!
        ) else (
            echo [ERROR] Ошибка сборки сервера для !GOOS!/!GOARCH!
        )
        
        echo.
    )
)

echo [SUCCESS] Все Go бинарники собраны в: %OUTPUT_DIR%\go-binaries\
goto :eof

:build_tauri_platform
set "TARGET=%~1"
set "PLATFORM_NAME=%~2"
set "GO_OS=%~3"
set "GO_ARCH=%~4"

echo.
echo ========================================
echo [INFO] Сборка для !PLATFORM_NAME! (!TARGET!)
echo [DEBUG] TARGET=!TARGET!, PLATFORM_NAME=!PLATFORM_NAME!
echo ========================================

:: Check if cross-compilation is possible
:: Only skip Linux and macOS targets, Windows should build
set "SKIP_BUILD=0"
if "!TARGET!"=="x86_64-unknown-linux-gnu" (
    set "SKIP_BUILD=1"
    echo [WARNING] Кросс-компиляция Linux с Windows требует настроенного sysroot
    echo [WARNING] Для сборки Linux используйте WSL или Linux машину
)
if "!TARGET!"=="x86_64-apple-darwin" (
    set "SKIP_BUILD=1"
    echo [WARNING] Кросс-компиляция macOS с Windows невозможна
    echo [WARNING] Для сборки macOS используйте macOS машину или CI/CD (GitHub Actions)
)
if "!TARGET!"=="aarch64-apple-darwin" (
    set "SKIP_BUILD=1"
    echo [WARNING] Кросс-компиляция macOS ARM64 с Windows невозможна
    echo [WARNING] Для сборки macOS ARM64 используйте macOS машину или CI/CD (GitHub Actions)
)

if "!SKIP_BUILD!"=="1" (
    echo [SKIP] Пропуск сборки для !PLATFORM_NAME!
    goto :eof
)

:: Windows and other targets should continue
echo [DEBUG] No skip condition matched, continuing with build for !TARGET!...

:: Save Tauri directory (should be client-package-tauri)
set TAURI_DIR=%ROOT_DIR%\client-package-tauri

:: Download wintun.dll only for Windows
if "!TARGET!"=="x86_64-pc-windows-msvc" (
    if not exist "%TAURI_DIR%\src-tauri\resources\wintun.dll" (
        echo [INFO] Загрузка wintun.dll для Windows...
        cd /d "%TAURI_DIR%"
        powershell -ExecutionPolicy Bypass -File "download-wintun.ps1" >nul 2>&1
    )
)

:: Build Go client for this platform
:: Tauri 2.0 automatically adds platform suffix to externalBin
:: Format: whispera-go-client-{target-triple}[.exe]
set "GO_CLIENT_NAME=whispera-go-client-!TARGET!"
if "!GO_OS!"=="windows" (
    set "GO_CLIENT_PATH=%TAURI_DIR%\src-tauri\resources\!GO_CLIENT_NAME!.exe"
) else (
    set "GO_CLIENT_PATH=%TAURI_DIR%\src-tauri\resources\!GO_CLIENT_NAME!"
)

if not exist "!GO_CLIENT_PATH!" (
    echo [INFO] Сборка Go клиента для %PLATFORM_NAME%...
    cd /d "%ROOT_DIR%"
    set GOOS=!GO_OS!
    set GOARCH=!GO_ARCH!
    go build -ldflags="-s -w" -o "!GO_CLIENT_PATH!" .\cmd\client
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] Ошибка сборки Go клиента для %PLATFORM_NAME%
        cd /d "%TAURI_DIR%"
        exit /b 1
    )
    echo [SUCCESS] Go клиент собран: !GO_CLIENT_NAME!
) else (
    echo [INFO] Go клиент для %PLATFORM_NAME% уже существует: !GO_CLIENT_NAME!
)

:: Копируем Go клиент в bin для sidecar (как в run-dev.bat)
if "!GO_OS!"=="windows" (
    if not exist "%TAURI_DIR%\src-tauri\bin" mkdir "%TAURI_DIR%\src-tauri\bin"
    set "BIN_CLIENT_PATH=%TAURI_DIR%\src-tauri\bin\!GO_CLIENT_NAME!.exe"
    if exist "!GO_CLIENT_PATH!" (
        copy /Y "!GO_CLIENT_PATH!" "!BIN_CLIENT_PATH!" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            echo [INFO] Go клиент скопирован в bin для sidecar: !GO_CLIENT_NAME!.exe
        )
    )
)

echo [INFO] Сборка Tauri приложения...
cd /d "%TAURI_DIR%"
call npm run tauri build -- --target !TARGET!
set BUILD_EXIT_CODE=!ERRORLEVEL!
if !BUILD_EXIT_CODE! NEQ 0 (
    echo [WARNING] Ошибка сборки для %PLATFORM_NAME% (код выхода: !BUILD_EXIT_CODE!)
    exit /b 1
)

:: Copy results
set "BUNDLE_DIR=src-tauri\target\!TARGET!\release\bundle"
if exist "!BUNDLE_DIR!" (
    set "PLATFORM_DIR=..\%OUTPUT_DIR%\%PLATFORM_NAME%"
    if not exist "!PLATFORM_DIR!" mkdir "!PLATFORM_DIR!"
    
    xcopy /E /I /Y "!BUNDLE_DIR!\*" "!PLATFORM_DIR!\" >nul 2>&1
    
    echo [SUCCESS] %PLATFORM_NAME% инсталляторы в: %PLATFORM_DIR%
    echo.
    echo Созданные файлы:
    dir /B "%PLATFORM_DIR%" 2>nul | findstr /R "\.msi$ \.exe$ \.AppImage$ \.deb$ \.dmg$"
)

goto :eof

:build_tauri_client
if defined SKIP_TAURI (
    echo [SKIP] Пропуск сборки Tauri клиента
    goto :eof
)

echo.
echo [INFO] Сборка Tauri клиента для всех платформ...
echo.

cd client-package-tauri

:: Install dependencies
if not exist "node_modules" (
    echo [INFO] Установка npm зависимостей...
    npm install
)

:: Note: wintun.dll и Go клиенты будут подготовлены для каждой платформы в build_tauri_platform
echo [INFO] Ресурсы будут подготовлены для каждой платформы

:: Install Rust targets
echo [INFO] Установка Rust targets...
rustup target add x86_64-pc-windows-msvc >nul 2>&1
rustup target add x86_64-unknown-linux-gnu >nul 2>&1
rustup target add x86_64-apple-darwin >nul 2>&1
rustup target add aarch64-apple-darwin >nul 2>&1

:: Build platforms
call :build_tauri_platform "x86_64-pc-windows-msvc" "Windows-x64" "windows" "amd64"
call :build_tauri_platform "x86_64-unknown-linux-gnu" "Linux-x64" "linux" "amd64"
call :build_tauri_platform "x86_64-apple-darwin" "macOS-x64" "darwin" "amd64"
call :build_tauri_platform "aarch64-apple-darwin" "macOS-ARM64" "darwin" "arm64"

cd ..
goto :eof

:build_go_binaries_windows
echo.
echo [INFO] Сборка Go бинарников для Windows...
echo.

:: Build Windows binaries
echo [INFO] Сборка для windows/amd64...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o "%OUTPUT_DIR%\go-binaries\whispera-client-windows-amd64.exe" .\cmd\client
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Ошибка сборки клиента для windows/amd64
    exit /b 1
)
echo [SUCCESS] Клиент: %OUTPUT_DIR%\go-binaries\whispera-client-windows-amd64.exe

go build -ldflags="-s -w" -o "%OUTPUT_DIR%\go-binaries\whispera-server-windows-amd64.exe" .\cmd\server
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Ошибка сборки сервера для windows/amd64
    exit /b 1
)
echo [SUCCESS] Сервер: %OUTPUT_DIR%\go-binaries\whispera-server-windows-amd64.exe

echo.
echo [SUCCESS] Windows Go бинарники собраны в: %OUTPUT_DIR%\go-binaries\
goto :eof

:build_tauri_windows
if defined SKIP_TAURI (
    echo [SKIP] Пропуск сборки Tauri клиента
    goto :eof
)

echo.
echo [INFO] Сборка Tauri клиента для Windows...
echo.

cd client-package-tauri

:: Install dependencies
if not exist "node_modules" (
    echo [INFO] Установка npm зависимостей...
    npm install
)

:: Install Rust target for Windows
echo [INFO] Установка Rust target для Windows...
rustup target add x86_64-pc-windows-msvc >nul 2>&1

:: Build Windows platform
call :build_tauri_platform "x86_64-pc-windows-msvc" "Windows-x64" "windows" "amd64"

cd ..
goto :eof

