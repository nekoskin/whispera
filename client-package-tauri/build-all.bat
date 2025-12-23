@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo Whispera Client - Tauri Build Script
echo ========================================
echo.

:: Проверка Rust
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust/Cargo не найден в PATH
    echo Установите Rust: https://www.rust-lang.org/tools/install
    echo.
    echo Windows: Запустите rustup-init.exe
    echo Или через PowerShell: irm https://rust-lang.org/rustup-init.sh ^| iex
    pause
    exit /b 1
)

echo [INFO] Rust найден
cargo --version
echo.

:: Проверка Node.js
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js не найден в PATH
    echo Установите Node.js: https://nodejs.org/
    pause
    exit /b 1
)

echo [INFO] Node.js найден
node --version
npm --version
echo.

:: Проверка Go (для сборки Go клиента)
where go >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Go не найден, пропускаем сборку Go клиента
    echo Убедитесь, что whispera-go-client.exe уже собран
    set SKIP_GO_BUILD=1
) else (
    echo [INFO] Go найден
    go version
    echo.
)

:: Переход в корень проекта
cd /d "%~dp0\.."

:: Создание папки resources если её нет
if not exist "client-package-tauri\src-tauri\resources" (
    mkdir "client-package-tauri\src-tauri\resources"
    echo [INFO] Создана папка resources
)

:: Обязательная загрузка wintun.dll (для TUN режима на Windows)
if not exist "client-package-tauri\src-tauri\resources\wintun.dll" (
    echo [INFO] wintun.dll не найден, загружаем...
    powershell -ExecutionPolicy Bypass -File "client-package-tauri\download-wintun.ps1"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Не удалось загрузить wintun.dll автоматически
        echo [ERROR] wintun.dll обязателен для сборки!
        echo.
        echo Скачайте вручную:
        echo   https://github.com/WireGuard/wintun/releases/download/v0.14.1/wintun-x64.dll
        echo.
        echo Сохраните как: client-package-tauri\src-tauri\resources\wintun.dll
        echo.
        pause
        exit /b 1
    ) else (
        echo [SUCCESS] wintun.dll загружен
    )
    echo.
    
    :: Проверяем что файл действительно создан
    if not exist "client-package-tauri\src-tauri\resources\wintun.dll" (
        echo [ERROR] wintun.dll не найден в resources после загрузки
        echo [ERROR] wintun.dll обязателен для сборки!
        pause
        exit /b 1
    )
) else (
    echo [INFO] wintun.dll уже существует в resources
    echo.
)

:: Сборка Go клиента для Windows
if not defined SKIP_GO_BUILD (
    echo [INFO] Сборка Go клиента для Windows...
    set GOOS=windows
    set GOARCH=amd64
    go build -o client-package-tauri\src-tauri\resources\whispera-go-client.exe .\cmd\client
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Ошибка сборки Go клиента для Windows
        pause
        exit /b 1
    )
    echo [SUCCESS] Go клиент для Windows собран и помещен в resources
    echo.
    
    :: Проверяем что файл действительно создан
    if not exist "client-package-tauri\src-tauri\resources\whispera-go-client.exe" (
        echo [ERROR] Go клиент не найден в resources после сборки
        pause
        exit /b 1
    )
    
    echo [INFO] Go клиент готов для встраивания в Tauri приложение
    echo.
) else (
    :: Проверяем наличие Go клиента в resources
    if not exist "client-package-tauri\src-tauri\resources\whispera-go-client.exe" (
        echo [ERROR] Go клиент не найден в resources
        echo Убедитесь, что whispera-go-client.exe находится в client-package-tauri\src-tauri\resources\
        pause
        exit /b 1
    )
    echo [INFO] Используется существующий Go клиент из resources
    echo.
)

:: Переход в папку Tauri проекта
cd /d "%~dp0"

:: Установка зависимостей
echo [INFO] Установка зависимостей...
npm install
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Ошибка установки зависимостей
    pause
    exit /b 1
)
echo.

:: Выбор платформы для сборки
echo Выберите платформу для сборки:
echo 1. Windows
echo 2. Linux
echo 3. macOS
echo 4. Все платформы
echo.
set /p PLATFORM="Введите номер (1-4): "

if "%PLATFORM%"=="1" (
    echo [INFO] Сборка для Windows...
    npm run tauri build -- --target x86_64-pc-windows-msvc
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Ошибка сборки для Windows
        pause
        exit /b 1
    )
    echo [SUCCESS] Сборка для Windows завершена
    echo Результат: src-tauri\target\x86_64-pc-windows-msvc\release\
) else if "%PLATFORM%"=="2" (
    echo [INFO] Сборка для Linux...
    npm run tauri build -- --target x86_64-unknown-linux-gnu
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Ошибка сборки для Linux
        pause
        exit /b 1
    )
    echo [SUCCESS] Сборка для Linux завершена
    echo Результат: src-tauri\target\x86_64-unknown-linux-gnu\release\
) else if "%PLATFORM%"=="3" (
    echo [INFO] Сборка для macOS...
    npm run tauri build -- --target x86_64-apple-darwin
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Ошибка сборки для macOS
        pause
        exit /b 1
    )
    echo [SUCCESS] Сборка для macOS завершена
    echo Результат: src-tauri\target\x86_64-apple-darwin\release\
) else if "%PLATFORM%"=="4" (
    echo [INFO] Сборка для всех платформ...
    
    echo [INFO] Windows...
    npm run tauri build -- --target x86_64-pc-windows-msvc
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Ошибка сборки для Windows
    )
    
    echo [INFO] Linux...
    npm run tauri build -- --target x86_64-unknown-linux-gnu
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Ошибка сборки для Linux
    )
    
    echo [INFO] macOS...
    npm run tauri build -- --target x86_64-apple-darwin
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Ошибка сборки для macOS
    )
    
    echo [SUCCESS] Сборка завершена
) else (
    echo [ERROR] Неверный выбор
    pause
    exit /b 1
)

echo.
echo ========================================
echo Сборка завершена!
echo ========================================
pause

