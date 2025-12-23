@echo off
chcp 65001 >nul
echo ========================================
echo Whispera Client - Run
echo ========================================
echo.

cd /d "%~dp0"

:: Проверяем наличие собранного приложения
if exist "src-tauri\target\release\whispera-client.exe" (
    echo [INFO] Запуск собранного приложения...
    start "" "src-tauri\target\release\whispera-client.exe"
    echo [SUCCESS] Приложение запущено
) else if exist "src-tauri\target\debug\whispera-client.exe" (
    echo [INFO] Запуск debug версии...
    start "" "src-tauri\target\debug\whispera-client.exe"
    echo [SUCCESS] Приложение запущено
) else (
    echo [ERROR] Приложение не собрано
    echo.
    echo Выберите действие:
    echo 1. Запустить в режиме разработки (npm run tauri dev)
    echo 2. Собрать приложение (npm run tauri build)
    echo.
    set /p CHOICE="Введите номер (1 или 2): "
    
    if "!CHOICE!"=="1" (
        echo [INFO] Запуск в режиме разработки...
        npm run tauri dev
    ) else if "!CHOICE!"=="2" (
        echo [INFO] Сборка приложения...
        npm run tauri build
        echo.
        echo [INFO] После сборки запустите run.bat снова
    ) else (
        echo [ERROR] Неверный выбор
    )
)

pause

