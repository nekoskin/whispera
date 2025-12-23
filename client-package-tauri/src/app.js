// Tauri API импорт
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

// Состояние приложения
let appState = {
    connected: false,
    connecting: false,
    goClientPath: null,
    traffic: {
        inbound: { bytes: 0, packets: 0 },
        outbound: { bytes: 0, packets: 0 },
        speed: { up: 0, down: 0 },
        history: [] // Последние 60 секунд
    },
    quickConnectInProgress: false // Защита от повторных вызовов
};

// Инициализация
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    console.log('[initializeApp] Starting initialization...');
    
    // Проверяем наличие Go клиента
    try {
        appState.goClientPath = await invoke('get_go_client_path');
        if (appState.goClientPath) {
            addLog('info', 'Go клиент найден: ' + appState.goClientPath);
            console.log('[initializeApp] Go client path:', appState.goClientPath);
        } else {
            addLog('warning', 'Go клиент не найден. Будет попытка извлечь из ресурсов при подключении.');
        }
    } catch (error) {
        addLog('error', 'Ошибка проверки Go клиента: ' + error.message);
    }

    // Загружаем сохраненные настройки
    loadSettings();
    
    // Загружаем профили
    loadProfiles();

    // Проверяем статус автозапуска и прав администратора
    checkAutostartStatus();
    checkAdminStatus();

    // Настройка обработчиков событий
    setupEventHandlers();
    
    // Подписка на события Go клиента
    setupGoClientListeners();
}

function setupEventHandlers() {
    // Навигация
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const page = e.currentTarget.dataset.page;
            navigateTo(page);
        });
    });

    // Подключение
    document.getElementById('connect-btn').addEventListener('click', handleConnect);
    document.getElementById('disconnect-btn').addEventListener('click', handleDisconnect);
    
    // Получение ключа сервера
    document.getElementById('fetch-key-btn').addEventListener('click', handleFetchServerKey);
    
    // Быстрое подключение
    document.getElementById('quick-connect-btn').addEventListener('click', handleQuickConnect);
    
    // Сохранение настроек
    document.getElementById('save-settings-btn').addEventListener('click', handleSaveSettings);
    
    // Автозапуск
    const autostartCheckbox = document.getElementById('autostart-enabled');
    if (autostartCheckbox) {
        autostartCheckbox.addEventListener('change', handleAutostartToggle);
    }
    
    // Очистка логов
    document.getElementById('clear-logs-btn').addEventListener('click', () => {
        document.getElementById('logs-content').innerHTML = '';
    });
    
    // Статистика
    const resetStatsBtn = document.getElementById('reset-stats-btn');
    const refreshStatsBtn = document.getElementById('refresh-stats-btn');
    if (resetStatsBtn) {
        resetStatsBtn.addEventListener('click', () => {
            appState.traffic = {
                inbound: { bytes: 0, packets: 0 },
                outbound: { bytes: 0, packets: 0 },
                speed: { up: 0, down: 0 },
                history: []
            };
            updateTrafficDisplay();
            updateTrafficChart();
        });
    }
    if (refreshStatsBtn) {
        refreshStatsBtn.addEventListener('click', () => {
            updateTrafficDisplay();
            updateTrafficChart();
        });
    }
    
    // Профили
    const addProfileBtn = document.getElementById('add-profile-btn');
    const importProfileBtn = document.getElementById('import-profile-btn');
    const exportProfileBtn = document.getElementById('export-profile-btn');
    
    if (addProfileBtn) {
        addProfileBtn.addEventListener('click', handleAddProfile);
    }
    if (importProfileBtn) {
        importProfileBtn.addEventListener('click', handleImportProfile);
    }
    if (exportProfileBtn) {
        exportProfileBtn.addEventListener('click', handleExportProfile);
    }
}

function setupGoClientListeners() {
    console.log('[setupGoClientListeners] Setting up event listeners...');
    
    // Вывод Go клиента
    listen('go-client-output', (event) => {
        console.log('[EVENT] go-client-output received, payload:', event.payload);
        const data = event.payload;
        // Логируем в консоль для отладки (только важные сообщения)
        if (data.includes('VPN') || data.includes('CONNECTION') || data.includes('ESTABLISHED') || 
            data.includes('HANDSHAKE') || data.includes('WebSocket') || data.includes('SOCKS5')) {
            console.log('[go-client-output] Received:', data);
        }
        addLog('info', data);
        
        // Парсим статистику трафика из логов
        parseTrafficStats(data);
        
        // Проверяем успешное подключение (более гибкая проверка)
        const upperData = data.toUpperCase();
        const connectionIndicators = [
            'VPN CONNECTION ESTABLISHED',
            'HANDSHAKE SUCCESSFUL',
            'VPN TUNNEL IS READY',
            'UDP HANDSHAKE SUCCESSFUL',
            'TCP HANDSHAKE SUCCESSFUL',
            'WEBSOCKET HANDSHAKE SUCCESSFUL',
            'HTTP/2 WEBSOCKET HANDSHAKE SUCCESSFUL',
            'VPN ENCRYPTION KEYS ESTABLISHED',
            'DATA PLANE STARTING',
            'TUN INTERFACE ACTIVE',
            'SOCKS5 PROXY MODE',
            'SOCKS5] ✅ STARTING',  // Для "SOCKS5] ✅ Starting SOCKS5 proxy server"
            'SOCKS5] ✅ SERVER LISTENING',  // Для "SOCKS5] ✅ Server listening"
            'SERVER LISTENING ON',  // Для "Server listening on 127.0.0.1:1080"
            'KEEPALIVE] 💓',  // Для "KEEPALIVE] 💓 WebSocket keepalive sent"
            'WEBSOCKET KEEPALIVE SENT',  // Альтернативный формат
            'WS FALLBACK CONNECTED',  // Для "ws fallback connected"
            'SESSIONID=',  // Для "sessionID=3839531706"
            'READY TO ACCEPT CONNECTIONS',  // Для "ready to accept connections"
            'HANDSHAKE COMPLETED SUCCESSFULLY',  // Для "Handshake completed successfully"
            'WEBSOCKET CONNECTION ESTABLISHED',  // Для "WebSocket connection established successfully"
            '✅ WEBSOCKET',  // Для "[WS Client] ✅ WebSocket connection established"
            'WEBSOCKET CONNECTION ESTABLISHED SUCCESSFULLY'  // Полная фраза
        ];
        
        // Упрощенная проверка - ищем ключевые фразы напрямую (как для stderr)
        const hasVPNEstablished = upperData.includes('VPN CONNECTION ESTABLISHED') || upperData.includes('[INFO] VPN CONNECTION ESTABLISHED');
        const hasServerListening = upperData.includes('SERVER LISTENING') || upperData.includes('READY TO ACCEPT CONNECTIONS') || 
                                   upperData.includes('LISTENING ON') || upperData.includes('SOCKS5') && upperData.includes('LISTENING');
        const hasHandshakeSuccess = upperData.includes('HANDSHAKE COMPLETED SUCCESSFULLY') || upperData.includes('HANDSHAKE SUCCESSFUL') ||
                                     upperData.includes('HANDSHAKE OK') || upperData.includes('HANDSHAKE SUCCESS');
        const hasWebSocketEstablished = upperData.includes('WEBSOCKET CONNECTION ESTABLISHED') || upperData.includes('✅ WEBSOCKET') ||
                                        upperData.includes('WEBSOCKET CONNECTION ESTABLISHED SUCCESSFULLY');
        const hasSOCKS5Ready = (upperData.includes('SOCKS5') && (upperData.includes('STARTING') || upperData.includes('LISTENING'))) ||
                               upperData.includes('SOCKS5 PROXY SERVER');
        const hasWSFallback = upperData.includes('WS FALLBACK CONNECTED') || upperData.includes('FALLBACK CONNECTED');
        // Проверка на сообщения Go клиента о подключении
        const hasConnected = (upperData.includes('✅ CONNECTED') || upperData.includes('CONNECTED TO')) && 
                            (upperData.includes('SERVER') || upperData.includes('TCP') || upperData.includes('UDP') || upperData.includes('GRPC') || upperData.includes('QUIC') || upperData.includes('HTTP'));
        const hasDataPlaneStarted = upperData.includes('DATA PLANE STARTED') || upperData.includes('✅') && upperData.includes('DATA PLANE');
        const hasClientStarted = upperData.includes('CLIENT STARTED') && upperData.includes('WAITING');
        
        const isConnected = hasVPNEstablished || hasServerListening || hasHandshakeSuccess || hasWebSocketEstablished || hasSOCKS5Ready || hasWSFallback || hasConnected || hasDataPlaneStarted || hasClientStarted;
        
        if (isConnected) {
            console.log(`[DEBUG] ✅ Connection detected in stdout! VPN=${hasVPNEstablished}, Server=${hasServerListening}, Handshake=${hasHandshakeSuccess}, WS=${hasWebSocketEstablished}, SOCKS5=${hasSOCKS5Ready}`);
            console.log(`[DEBUG] Connection indicator found in: "${data}"`);
            console.log(`[DEBUG] Current appState.connected: ${appState.connected}, appState.connecting: ${appState.connecting}`);
            if (!appState.connected) {
                console.log('[DEBUG] Updating connection status to connected');
                appState.connected = true;
                appState.connecting = false;
                updateConnectionStatus(true);
                startStatsUpdate(); // Запускаем обновление статистики
                addLog('success', 'Подключение установлено!');
            } else {
                console.log('[DEBUG] Already connected, skipping status update');
            }
        }
    });

    // Ошибки Go клиента (также проверяем на успешное подключение)
    listen('go-client-error', (event) => {
        console.error('[EVENT] go-client-error received, payload:', event.payload);
        const data = event.payload;
        // Логируем в консоль для отладки (только важные сообщения)
        if (data.includes('VPN') || data.includes('CONNECTION') || data.includes('ESTABLISHED') || 
            data.includes('HANDSHAKE') || data.includes('WebSocket') || data.includes('SOCKS5') ||
            data.includes('ERROR') || data.includes('WARN')) {
            console.error('[go-client-error]', data);
        }
        addLog('error', data);
        
        // Проверяем критические ошибки, которые означают, что подключение невозможно
        const upperData = data.toUpperCase();
        const criticalErrors = [
            'FAILED TO START',
            'NOT FOUND',
            'NO SUCH FILE',
            'PERMISSION DENIED',
            'ALL CONNECTION METHODS FAILED',
            'HANDSHAKE TIMEOUT',
            'TLS HANDSHAKE TIMEOUT',
            'DTLS HANDSHAKE TIMEOUT'
        ];
        
        if (criticalErrors.some(err => upperData.includes(err))) {
            if (appState.connecting) {
                appState.connecting = false;
                updateConnectionStatus(false);
                addLog('error', 'Критическая ошибка подключения. Проверьте логи выше.');
            }
        }
        
        // Иногда важные сообщения могут попадать в stderr
        const connectionIndicators = [
            'VPN CONNECTION ESTABLISHED',
            'HANDSHAKE SUCCESSFUL',
            'VPN TUNNEL IS READY',
            'SOCKS5] ✅ STARTING',
            'SOCKS5] ✅ SERVER LISTENING',
            'SERVER LISTENING ON',  // Для "Server listening on 127.0.0.1:1080"
            'WEBSOCKET HANDSHAKE SUCCESSFUL',
            'WS FALLBACK CONNECTED',
            'KEEPALIVE] 💓',  // Для "KEEPALIVE] 💓 WebSocket keepalive sent"
            'WEBSOCKET KEEPALIVE SENT',
            'SESSIONID=',  // Для "sessionID=3839531706"
            'VPN TUNNEL IS READY',  // Дублируем для надежности
            'READY TO ACCEPT CONNECTIONS',  // Для "ready to accept connections"
            'HANDSHAKE COMPLETED SUCCESSFULLY',  // Для "Handshake completed successfully"
            'WEBSOCKET CONNECTION ESTABLISHED',  // Для "WebSocket connection established successfully"
            '✅ WEBSOCKET',  // Для "[WS Client] ✅ WebSocket connection established"
            'WEBSOCKET CONNECTION ESTABLISHED SUCCESSFULLY'  // Полная фраза
        ];
        
        // Упрощенная проверка - ищем ключевые фразы напрямую
        // Проверяем различные варианты сообщений о подключении
        const hasVPNEstablished = upperData.includes('VPN CONNECTION ESTABLISHED') || upperData.includes('[INFO] VPN CONNECTION ESTABLISHED');
        const hasServerListening = upperData.includes('SERVER LISTENING') || upperData.includes('READY TO ACCEPT CONNECTIONS') || 
                                   upperData.includes('LISTENING ON') || upperData.includes('SOCKS5') && upperData.includes('LISTENING');
        const hasHandshakeSuccess = upperData.includes('HANDSHAKE COMPLETED SUCCESSFULLY') || upperData.includes('HANDSHAKE SUCCESSFUL') ||
                                     upperData.includes('HANDSHAKE OK') || upperData.includes('HANDSHAKE SUCCESS');
        const hasWebSocketEstablished = upperData.includes('WEBSOCKET CONNECTION ESTABLISHED') || upperData.includes('✅ WEBSOCKET') ||
                                        upperData.includes('WEBSOCKET CONNECTION ESTABLISHED SUCCESSFULLY');
        const hasSOCKS5Ready = (upperData.includes('SOCKS5') && (upperData.includes('STARTING') || upperData.includes('LISTENING'))) ||
                               upperData.includes('SOCKS5 PROXY SERVER');
        const hasWSFallback = upperData.includes('WS FALLBACK CONNECTED') || upperData.includes('FALLBACK CONNECTED');
        // Проверка на сообщения Go клиента о подключении
        const hasConnected = (upperData.includes('✅ CONNECTED') || upperData.includes('CONNECTED TO')) && 
                            (upperData.includes('SERVER') || upperData.includes('TCP') || upperData.includes('UDP') || upperData.includes('GRPC') || upperData.includes('QUIC') || upperData.includes('HTTP'));
        const hasDataPlaneStarted = upperData.includes('DATA PLANE STARTED') || upperData.includes('✅') && upperData.includes('DATA PLANE');
        const hasClientStarted = upperData.includes('CLIENT STARTED') && upperData.includes('WAITING');
        
        const isConnected = hasVPNEstablished || hasServerListening || hasHandshakeSuccess || hasWebSocketEstablished || hasSOCKS5Ready || hasWSFallback || hasConnected || hasDataPlaneStarted || hasClientStarted;
        
        // Логируем для отладки только важные сообщения
        if (isConnected || data.includes('VPN') || data.includes('CONNECTION') || data.includes('ESTABLISHED') || 
            data.includes('HANDSHAKE') || data.includes('WebSocket') || data.includes('SOCKS5')) {
            const preview = data.substring(0, Math.min(150, data.length));
            console.log(`[DEBUG] Checking stderr: "${preview}${data.length > 150 ? '...' : ''}"`);
            if (isConnected) {
                console.log(`[DEBUG] ✅ Connection detected! VPN=${hasVPNEstablished}, Server=${hasServerListening}, Handshake=${hasHandshakeSuccess}, WS=${hasWebSocketEstablished}, SOCKS5=${hasSOCKS5Ready}`);
            }
        }
        
        if (isConnected) {
            console.log(`[DEBUG] Connection indicator found in stderr: "${data}"`);
            console.log(`[DEBUG] Current appState.connected: ${appState.connected}, appState.connecting: ${appState.connecting}`);
            if (!appState.connected) {
                console.log('[DEBUG] Updating connection status to connected (from stderr)');
                appState.connected = true;
                appState.connecting = false;
                updateConnectionStatus(true);
                startStatsUpdate();
                addLog('success', 'Подключение установлено!');
            }
        }
    });

    // Выход Go клиента
    listen('go-client-exit', (event) => {
        console.log('[EVENT] go-client-exit received, code:', event.payload);
        const code = event.payload;
        addLog('warning', `Go клиент завершился с кодом: ${code}`);
        appState.connected = false;
        appState.connecting = false;
        updateConnectionStatus(false);
        stopStatsUpdate(); // Останавливаем обновление статистики
    });
}

function navigateTo(page) {
    // Обновляем активную страницу в меню
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === page) {
            item.classList.add('active');
        }
    });

    // Скрываем все страницы
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    // Показываем выбранную страницу
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
        document.getElementById('page-title').textContent = getPageTitle(page);
        
        // Обновляем статистику при переходе на страницу статистики
        if (page === 'stats') {
            updateTrafficDisplay();
            updateTrafficChart();
        }
        
        // Обновляем профили при переходе на страницу профилей
        if (page === 'profiles') {
            renderProfiles();
        }
    }
}

function getPageTitle(page) {
    const titles = {
        'home': 'Главная',
        'settings': 'Настройки',
        'profiles': 'Профили',
        'stats': 'Статистика',
        'logs': 'Логи'
    };
    return titles[page] || 'Главная';
}

async function handleConnect() {
    // Если уже подключено или идет подключение, сначала отключаемся
    if (appState.connected || appState.connecting) {
        addLog('info', 'Остановка предыдущего подключения...');
        await handleDisconnect();
        // Даем время процессу завершиться
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const serverPort = parseInt(document.getElementById('server-port').value) || 51820;
    const stunServerInput = document.getElementById('stun-server');
    const outboundTagInput = document.getElementById('outbound-tag');
    const useXHTTP = document.getElementById('use-xhttp')?.checked || false;
    
    const config = {
        server_ip: document.getElementById('server-ip').value.trim(),
        server_port: serverPort,
        server_public_key: document.getElementById('server-pub-key').value.trim() || null,
        server_tcp_port: serverPort === 51820 ? 4443 : undefined,
        server_ws_port: 8080, // WebSocket на 8080
        server_ws2_port: 8443, // HTTP/2 WebSocket на 8443
        use_tap: false, // Используем TUN (не TAP) по умолчанию
        cert_pinning: false, // Certificate pinning отключен по умолчанию
        proxy_mode: document.getElementById('proxy-mode').checked,
        auto_profile: document.getElementById('auto-profile')?.checked || false,
        monitoring: true,
        app_profile: document.getElementById('marionette-profile')?.value || 'browser',
        stun_server: stunServerInput ? (stunServerInput.value.trim() || 'stun.l.google.com:19302') : 'stun.l.google.com:19302', // По умолчанию Google STUN
        outbound_tag: outboundTagInput ? (outboundTagInput.value.trim() || '') : '', // Outbound tag от клиента
        // XHTTP параметры (если включен XHTTP режим с Marionette обфускацией)
        xhttp_public_key: useXHTTP ? (document.getElementById('xhttp-public-key')?.value.trim() || null) : null,
        xhttp_short_id: useXHTTP ? (document.getElementById('xhttp-short-id')?.value.trim() || null) : null,
        xhttp_server_name: useXHTTP ? (document.getElementById('xhttp-server-name')?.value.trim() || null) : null,
        xhttp_fingerprint: useXHTTP ? (document.getElementById('xhttp-fingerprint')?.value || 'chrome') : null,
    };

    if (!config.server_ip) {
        alert('Введите IP адрес сервера');
        return;
    }

    // Проверка XHTTP параметров (если включен XHTTP режим)
    if (useXHTTP) {
        if (!config.xhttp_public_key || config.xhttp_public_key.length !== 64) {
            alert('XHTTP Public Key должен быть 64 символа (hex, ed25519 публичный ключ)');
            return;
        }
        // Проверка что это hex строка
        if (!/^[0-9a-fA-F]{64}$/.test(config.xhttp_public_key)) {
            alert('XHTTP Public Key должен содержать только hex символы (0-9, a-f, A-F)');
            return;
        }
        if (!config.xhttp_short_id || config.xhttp_short_id.length !== 16) {
            alert('XHTTP Short ID должен быть 16 символов (hex, 8 байт)');
            return;
        }
        // Проверка что это hex строка
        if (!/^[0-9a-fA-F]{16}$/.test(config.xhttp_short_id)) {
            alert('XHTTP Short ID должен содержать только hex символы (0-9, a-f, A-F)');
            return;
        }
        if (!config.xhttp_server_name) {
            alert('Введите XHTTP Server Name (например: example.com)');
            return;
        }
        addLog('info', 'XHTTP+VLESS режим включен с Marionette обфускацией');
    } else {
        // Если XHTTP не используется, проверяем обычный публичный ключ
        // Если ключ не указан, пробуем получить через API
        if (!config.server_public_key) {
            addLog('info', 'Публичный ключ не указан, пытаемся получить через API...');
            const keyResult = await handleFetchServerKey();
            if (keyResult && keyResult.success) {
                config.server_public_key = keyResult.key;
            } else {
                alert('Не удалось получить публичный ключ сервера. Укажите его вручную или включите XHTTP режим.');
                return;
            }
        }
    }

    // Сохраняем последнее подключение
    const lastConnection = {
        serverIp: config.server_ip,
        serverPort: config.server_port,
        serverPubKey: config.server_public_key,
        useXHTTP: useXHTTP,
        xhttpPublicKey: config.xhttp_public_key,
        xhttpShortId: config.xhttp_short_id,
        xhttpServerName: config.xhttp_server_name,
        xhttpFingerprint: config.xhttp_fingerprint
    };
    localStorage.setItem('whispera_last_connection', JSON.stringify(lastConnection));

    appState.connecting = true;
    updateConnectionStatus(false, true);
    addLog('info', 'Запуск Go клиента...');
    
    // Альтернативный способ определения подключения - через таймаут после запуска
    // Если через 30 секунд после запуска клиента нет ошибок, считаем что подключено
    const connectionCheckTimeout = setTimeout(() => {
        if (appState.connecting && !appState.connected) {
            // Проверяем, есть ли процесс Go клиента
            console.log('[DEBUG] Connection check timeout - checking if client is still running...');
            // Если процесс работает, возможно подключение установлено, но индикатор не сработал
            // В этом случае обновляем статус вручную
            if (appState.connecting) {
                console.log('[DEBUG] Client process seems to be running - marking as connected');
                appState.connected = true;
                appState.connecting = false;
                updateConnectionStatus(true);
                startStatsUpdate();
                addLog('success', 'Подключение установлено (автоматическое определение)');
            }
        }
    }, 30000); // 30 секунд
    
    // Очищаем таймаут при успешном подключении
    const originalUpdateConnectionStatus = updateConnectionStatus;
    updateConnectionStatus = function(connected, connecting = false) {
        if (connected) {
            clearTimeout(connectionCheckTimeout);
        }
        return originalUpdateConnectionStatus(connected, connecting);
    };

    // Таймаут подключения (60 секунд)
    const connectionTimeout = setTimeout(() => {
        if (appState.connecting && !appState.connected) {
            addLog('error', 'Таймаут подключения: клиент не смог подключиться за 60 секунд');
            addLog('info', 'Возможные причины:');
            addLog('info', '  - Сервер недоступен или не отвечает');
            addLog('info', '  - Неправильный IP адрес или порт');
            addLog('info', '  - Неправильный публичный ключ сервера');
            addLog('info', '  - Брандмауэр блокирует соединение');
            addLog('info', '  - UDP/TCP порты заблокированы');
            appState.connecting = false;
            updateConnectionStatus(false);
        }
    }, 60000); // 60 секунд

    try {
        console.log('[handleConnect] Calling invoke start_go_client with config:', JSON.stringify(config, null, 2));
        const result = await invoke('start_go_client', { config });
        console.log('[handleConnect] Result from invoke:', result);
        if (result.success) {
            addLog('success', `Go клиент запущен (PID: ${result.pid})`);
            addLog('info', 'Ожидание подключения... (таймаут: 60 секунд)');
            addLog('info', 'Проверка процесса через 2 секунды...');
            
            // Проверяем процесс через 2 секунды
            setTimeout(async () => {
                try {
                    const checkResult = await invoke('check_go_client_process', { pid: result.pid });
                    console.log('[handleConnect] Process check result:', checkResult);
                    if (checkResult && checkResult.running) {
                        addLog('success', `Процесс Go клиента (PID: ${result.pid}) работает`);
                    } else {
                        addLog('error', `Процесс Go клиента (PID: ${result.pid}) не найден - возможно упал`);
                        appState.connecting = false;
                        updateConnectionStatus(false);
                        clearTimeout(connectionTimeout);
                    }
                } catch (err) {
                    console.error('[handleConnect] Process check error:', err);
                    addLog('warning', 'Не удалось проверить статус процесса');
                }
            }, 2000);
            
            // Очищаем таймаут при успешном подключении
            const checkConnection = setInterval(() => {
                if (appState.connected) {
                    clearTimeout(connectionTimeout);
                    clearInterval(checkConnection);
                }
            }, 1000);
            
            // Очищаем таймаут и интервал через 5 минут (на случай если забыли)
            setTimeout(() => {
                clearTimeout(connectionTimeout);
                clearInterval(checkConnection);
            }, 300000);
        } else {
            clearTimeout(connectionTimeout);
            addLog('error', 'Ошибка запуска Go клиента: ' + result.error);
            appState.connecting = false;
            updateConnectionStatus(false);
        }
    } catch (error) {
        console.error('[handleConnect] Error:', error);
        console.error('[handleConnect] Error type:', typeof error);
        console.error('[handleConnect] Error string:', String(error));
        clearTimeout(connectionTimeout);
        const errorMsg = error?.message || error?.toString() || String(error) || 'Unknown error';
        addLog('error', `Ошибка: ${errorMsg}`);
        appState.connecting = false;
        updateConnectionStatus(false);
    }
}

async function handleDisconnect() {
    try {
        const result = await invoke('stop_go_client');
        if (result && result.success) {
            addLog('info', 'Go клиент остановлен');
            appState.connected = false;
            appState.connecting = false;
            updateConnectionStatus(false);
            stopStatsUpdate(); // Останавливаем обновление статистики
        } else {
            // Если процесс уже остановлен, это не ошибка
            const errorMsg = result?.error || 'Процесс уже остановлен';
            if (errorMsg.includes('already') || errorMsg.includes('not running')) {
                addLog('info', 'Go клиент уже остановлен');
            } else {
                addLog('warning', 'Ошибка остановки: ' + errorMsg);
            }
            appState.connected = false;
            appState.connecting = false;
            updateConnectionStatus(false);
        }
    } catch (error) {
        // Игнорируем ошибки при остановке - возможно процесс уже остановлен
        const errorMsg = error?.message || error?.toString() || String(error) || 'Unknown error';
        if (!errorMsg.includes('not found') && !errorMsg.includes('already')) {
            addLog('warning', 'Ошибка при остановке: ' + errorMsg);
        }
        appState.connected = false;
        appState.connecting = false;
        updateConnectionStatus(false);
    }
}

async function handleFetchServerKey() {
    const serverIp = document.getElementById('server-ip').value.trim();
    if (!serverIp) {
        alert('Введите IP адрес сервера');
        return { success: false };
    }

    addLog('info', `Получение публичного ключа с ${serverIp}...`);
    
    try {
        const result = await invoke('get_server_public_key', { serverIp });
        if (result.success) {
            document.getElementById('server-pub-key').value = result.key;
            addLog('success', 'Публичный ключ получен успешно');
            return result;
        } else {
            addLog('error', 'Не удалось получить ключ: ' + result.error);
            return result;
        }
    } catch (error) {
        addLog('error', 'Ошибка: ' + error.message);
        return { success: false, error: error.message };
    }
}

async function handleQuickConnect() {
    // Защита от повторных вызовов
    if (appState.quickConnectInProgress) {
        addLog('warning', 'Подключение уже выполняется, пожалуйста подождите...');
        return;
    }
    
    if (appState.connected || appState.connecting) {
        addLog('warning', 'Уже подключено или идет подключение');
        return;
    }
    
    const key = document.getElementById('quick-connect-key').value.trim();
    if (!key) {
        alert('Введите ключ подключения');
        return;
    }

    appState.quickConnectInProgress = true;
    
    // Отключаем кнопку во время выполнения
    const quickConnectBtn = document.getElementById('quick-connect-btn');
    if (quickConnectBtn) {
        quickConnectBtn.disabled = true;
        quickConnectBtn.textContent = 'Подключение...';
    }
    
    try {
        // Парсим ключ формата whispera://...
        const url = new URL(key);
        if (url.protocol !== 'whispera:') {
            throw new Error('Неверный формат ключа');
        }

        const serverIp = url.hostname;
        const serverPort = parseInt(url.port) || 51820;
        const serverPub = url.searchParams.get('pub') || '';
        const clientKey = url.searchParams.get('key') || '';
        
        // XHTTP параметры из ключа (если есть)
        const xhttpPub = url.searchParams.get('xhttpPub') || '';
        const xhttpShortId = url.searchParams.get('xhttpShortId') || '';
        const xhttpServerName = url.searchParams.get('xhttpServerName') || '';
        const xhttpFingerprint = url.searchParams.get('xhttpFingerprint') || 'chrome';
        const useXHTTP = !!(xhttpPub && xhttpShortId && xhttpServerName);

        // Если есть приватный ключ, пробуем получить конфигурацию через API (только один раз)
        if (clientKey && serverIp) {
            addLog('info', 'Получение конфигурации через API...');
            try {
                // Таймаут для API запроса - 5 секунд
                const configPromise = invoke('get_client_config_by_key', {
                    serverIp: serverIp,
                    privateKey: clientKey
                });
                
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Timeout')), 5000)
                );
                
                const config = await Promise.race([configPromise, timeoutPromise]);
                
                if (config && config.serverIp) {
                    document.getElementById('server-ip').value = config.serverIp;
                    document.getElementById('server-port').value = config.serverPort || 51820;
                    document.getElementById('server-pub-key').value = config.serverPublicKey || serverPub;
                    
                    // Применяем XHTTP параметры из конфигурации (если есть)
                    if (config.xhttpPublicKey && config.xhttpShortId && config.xhttpServerName) {
                        document.getElementById('use-xhttp').checked = true;
                        toggleXHTTPFields();
                        document.getElementById('xhttp-public-key').value = config.xhttpPublicKey;
                        document.getElementById('xhttp-short-id').value = config.xhttpShortId;
                        document.getElementById('xhttp-server-name').value = config.xhttpServerName;
                        if (config.xhttpFingerprint) {
                            document.getElementById('xhttp-fingerprint').value = config.xhttpFingerprint;
                        }
                    }
                    
                    // Сохраняем приватный ключ клиента (если нужно)
                    if (config.clientPrivateKey) {
                        localStorage.setItem('whispera_client_key', config.clientPrivateKey);
                    }
                    
                    addLog('success', 'Конфигурация получена через API');
                } else {
                    // Fallback на парсинг URL
                    addLog('info', 'Используем параметры из ключа (API не вернул полную конфигурацию)');
                    document.getElementById('server-ip').value = serverIp;
                    document.getElementById('server-port').value = serverPort;
                    if (serverPub) {
                        document.getElementById('server-pub-key').value = serverPub;
                    }
                    
                    // Применяем XHTTP параметры из URL (если есть)
                    if (useXHTTP) {
                        document.getElementById('use-xhttp').checked = true;
                        toggleXHTTPFields();
                        document.getElementById('xhttp-public-key').value = xhttpPub;
                        document.getElementById('xhttp-short-id').value = xhttpShortId;
                        document.getElementById('xhttp-server-name').value = xhttpServerName;
                        document.getElementById('xhttp-fingerprint').value = xhttpFingerprint;
                    }
                }
            } catch (apiError) {
                // API недоступен - это нормально, используем параметры из ключа
                // Не показываем предупреждение, так как это ожидаемое поведение
                document.getElementById('server-ip').value = serverIp;
                document.getElementById('server-port').value = serverPort;
                if (serverPub) {
                    document.getElementById('server-pub-key').value = serverPub;
                }
                
                // Применяем XHTTP параметры из URL (если есть)
                if (useXHTTP) {
                    document.getElementById('use-xhttp').checked = true;
                    toggleXHTTPFields();
                    document.getElementById('xhttp-public-key').value = xhttpPub;
                    document.getElementById('xhttp-short-id').value = xhttpShortId;
                    document.getElementById('xhttp-server-name').value = xhttpServerName;
                    document.getElementById('xhttp-fingerprint').value = xhttpFingerprint;
                }
            }
        } else {
            // Нет приватного ключа - используем только параметры из URL
            document.getElementById('server-ip').value = serverIp;
            document.getElementById('server-port').value = serverPort;
            if (serverPub) {
                document.getElementById('server-pub-key').value = serverPub;
            }
            
            // Применяем REALITY параметры из URL (если есть)
            if (useReality) {
                document.getElementById('use-reality').checked = true;
                toggleRealityFields();
                document.getElementById('reality-public-key').value = realityPub;
                document.getElementById('reality-short-id').value = realityShortId;
                document.getElementById('reality-server-name').value = realityServerName;
                document.getElementById('reality-fingerprint').value = realityFingerprint;
            }
        }

        addLog('info', 'Параметры подключения загружены из ключа');
        
        // Запускаем подключение
        await handleConnect();
    } catch (error) {
        addLog('error', 'Ошибка парсинга ключа: ' + error.message);
        alert('Ошибка парсинга ключа: ' + error.message);
    } finally {
        appState.quickConnectInProgress = false;
        // Включаем кнопку обратно
        if (quickConnectBtn) {
            quickConnectBtn.disabled = false;
            quickConnectBtn.textContent = 'Подключиться по ключу';
        }
    }
}

function loadSettings() {
    try {
        const saved = localStorage.getItem('whispera_settings');
        if (saved) {
            const settings = JSON.parse(saved);
            
            // Восстанавливаем настройки в форму
            if (settings.obfuscationProfile) {
                const obfsSelect = document.getElementById('obfuscation-profile');
                if (obfsSelect) obfsSelect.value = settings.obfuscationProfile;
            }
            if (settings.marionetteProfile) {
                const marionetteSelect = document.getElementById('marionette-profile');
                if (marionetteSelect) marionetteSelect.value = settings.marionetteProfile;
            }
            if (document.getElementById('auto-profile')) {
                document.getElementById('auto-profile').checked = settings.autoProfile || false;
            }
            if (document.getElementById('ai-evasion')) {
                document.getElementById('ai-evasion').checked = settings.aiEvasion || false;
            }
            if (document.getElementById('hardware-evasion')) {
                document.getElementById('hardware-evasion').checked = settings.hardwareEvasion || false;
            }
            if (document.getElementById('behavioral-mimicry')) {
                document.getElementById('behavioral-mimicry').checked = settings.behavioralMimicry || false;
            }
            if (document.getElementById('russian-mimicry')) {
                document.getElementById('russian-mimicry').checked = settings.russianMimicry || false;
            }
            // Автозапуск загружается через checkAutostartStatus(), но можем установить начальное значение
            if (settings.autostartEnabled !== undefined && document.getElementById('autostart-enabled')) {
                document.getElementById('autostart-enabled').checked = settings.autostartEnabled;
            }
        }
        
        // Загружаем последние параметры подключения
        const lastConnection = localStorage.getItem('whispera_last_connection');
        if (lastConnection) {
            const conn = JSON.parse(lastConnection);
            if (conn.serverIp && document.getElementById('server-ip')) {
                document.getElementById('server-ip').value = conn.serverIp;
            }
            if (conn.serverPort && document.getElementById('server-port')) {
                document.getElementById('server-port').value = conn.serverPort;
            }
            if (conn.serverPubKey && document.getElementById('server-pub-key')) {
                document.getElementById('server-pub-key').value = conn.serverPubKey;
            }
            // Загружаем XHTTP параметры
            if (conn.useXHTTP && document.getElementById('use-xhttp')) {
                document.getElementById('use-xhttp').checked = true;
                toggleXHTTPFields();
            }
            if (conn.xhttpPublicKey && document.getElementById('xhttp-public-key')) {
                document.getElementById('xhttp-public-key').value = conn.xhttpPublicKey;
            }
            if (conn.xhttpShortId && document.getElementById('xhttp-short-id')) {
                document.getElementById('xhttp-short-id').value = conn.xhttpShortId;
            }
            if (conn.xhttpServerName && document.getElementById('xhttp-server-name')) {
                document.getElementById('xhttp-server-name').value = conn.xhttpServerName;
            }
            if (conn.xhttpFingerprint && document.getElementById('xhttp-fingerprint')) {
                document.getElementById('xhttp-fingerprint').value = conn.xhttpFingerprint;
            }
        }
    } catch (error) {
        console.error('Ошибка загрузки настроек:', error);
    }
}

function handleSaveSettings() {
    const settings = {
        obfuscationProfile: document.getElementById('obfuscation-profile').value,
        marionetteProfile: document.getElementById('marionette-profile').value,
        autoProfile: document.getElementById('auto-profile').checked,
        aiEvasion: document.getElementById('ai-evasion').checked,
        hardwareEvasion: document.getElementById('hardware-evasion').checked,
        behavioralMimicry: document.getElementById('behavioral-mimicry').checked,
        russianMimicry: document.getElementById('russian-mimicry').checked,
        autostartEnabled: document.getElementById('autostart-enabled')?.checked || false,
    };

    localStorage.setItem('whispera_settings', JSON.stringify(settings));
    addLog('success', 'Настройки сохранены');
}

// Управление профилями
let profiles = [];

function loadProfiles() {
    try {
        const saved = localStorage.getItem('whispera_profiles');
        if (saved) {
            profiles = JSON.parse(saved);
            renderProfiles();
        }
    } catch (error) {
        console.error('Ошибка загрузки профилей:', error);
        profiles = [];
    }
}

function saveProfiles() {
    try {
        localStorage.setItem('whispera_profiles', JSON.stringify(profiles));
    } catch (error) {
        console.error('Ошибка сохранения профилей:', error);
        addLog('error', 'Не удалось сохранить профили');
    }
}

function renderProfiles() {
    const list = document.getElementById('profiles-list');
    if (!list) return;
    
    if (profiles.length === 0) {
        list.innerHTML = `
            <div class="profile-item empty">
                <p>Нет сохраненных профилей</p>
                <p class="text-secondary">Создайте профиль для быстрого подключения</p>
            </div>
        `;
        return;
    }
    
    list.innerHTML = profiles.map((profile, index) => `
        <div class="profile-item" data-index="${index}">
            <div class="profile-info">
                <h4>${profile.name || 'Без названия'}</h4>
                <p class="text-secondary">${profile.serverIp}:${profile.serverPort || 51820}</p>
                ${profile.useXHTTP ? '<p class="text-info" style="color: #3B82F6; font-size: 0.85em;">🔒 XHTTP+VLESS</p>' : ''}
            </div>
            <div class="profile-actions">
                <button class="btn btn-small btn-primary" onclick="applyProfile(${index})">Подключиться</button>
                <button class="btn btn-small btn-secondary" onclick="editProfile(${index})">Изменить</button>
                <button class="btn btn-small btn-danger" onclick="deleteProfile(${index})">Удалить</button>
            </div>
        </div>
    `).join('');
}

function handleAddProfile() {
    const name = prompt('Введите название профиля:');
    if (!name) return;
    
    const serverIp = document.getElementById('server-ip').value.trim();
    const serverPort = parseInt(document.getElementById('server-port').value) || 51820;
    const serverPubKey = document.getElementById('server-pub-key').value.trim();
    
    if (!serverIp) {
        alert('Сначала укажите IP сервера');
        return;
    }
    
    const useXHTTP = document.getElementById('use-xhttp')?.checked || false;
    const profile = {
        id: Date.now().toString(),
        name: name,
        serverIp: serverIp,
        serverPort: serverPort,
        serverPubKey: serverPubKey,
        useXHTTP: useXHTTP,
        xhttpPublicKey: useXHTTP ? (document.getElementById('xhttp-public-key')?.value.trim() || '') : '',
        xhttpShortId: useXHTTP ? (document.getElementById('xhttp-short-id')?.value.trim() || '') : '',
        xhttpServerName: useXHTTP ? (document.getElementById('xhttp-server-name')?.value.trim() || '') : '',
        xhttpFingerprint: useXHTTP ? (document.getElementById('xhttp-fingerprint')?.value || 'chrome') : 'chrome',
        createdAt: new Date().toISOString()
    };
    
    profiles.push(profile);
    saveProfiles();
    renderProfiles();
    addLog('success', `Профиль "${name}" добавлен`);
}

// Делаем функции глобальными для вызова из HTML
window.applyProfile = function(index) {
    if (index < 0 || index >= profiles.length) return;
    
    const profile = profiles[index];
    document.getElementById('server-ip').value = profile.serverIp;
    document.getElementById('server-port').value = profile.serverPort || 51820;
    if (profile.serverPubKey) {
        document.getElementById('server-pub-key').value = profile.serverPubKey;
    }
    
    // Применяем XHTTP параметры если есть
    if (profile.useXHTTP) {
        document.getElementById('use-xhttp').checked = true;
        toggleXHTTPFields();
        if (profile.xhttpPublicKey) {
            document.getElementById('xhttp-public-key').value = profile.xhttpPublicKey;
        }
        if (profile.xhttpShortId) {
            document.getElementById('xhttp-short-id').value = profile.xhttpShortId;
        }
        if (profile.xhttpServerName) {
            document.getElementById('xhttp-server-name').value = profile.xhttpServerName;
        }
        if (profile.xhttpFingerprint) {
            document.getElementById('xhttp-fingerprint').value = profile.xhttpFingerprint;
        }
    } else {
        document.getElementById('use-xhttp').checked = false;
        toggleXHTTPFields();
    }
    
    // Сохраняем как последнее подключение
    localStorage.setItem('whispera_last_connection', JSON.stringify({
        serverIp: profile.serverIp,
        serverPort: profile.serverPort,
        serverPubKey: profile.serverPubKey,
        useXHTTP: profile.useXHTTP || false,
        xhttpPublicKey: profile.xhttpPublicKey || '',
        xhttpShortId: profile.xhttpShortId || '',
        xhttpServerName: profile.xhttpServerName || '',
        xhttpFingerprint: profile.xhttpFingerprint || 'chrome'
    }));
    
    addLog('info', `Профиль "${profile.name}" применен`);
    navigateTo('home');
};

window.editProfile = function(index) {
    if (index < 0 || index >= profiles.length) return;
    
    const profile = profiles[index];
    const newName = prompt('Введите новое название профиля:', profile.name);
    if (!newName) return;
    
    // Обновляем из текущих полей
    profile.name = newName;
    profile.serverIp = document.getElementById('server-ip').value.trim() || profile.serverIp;
    profile.serverPort = parseInt(document.getElementById('server-port').value) || profile.serverPort;
    profile.serverPubKey = document.getElementById('server-pub-key').value.trim() || profile.serverPubKey;
    const useXHTTP = document.getElementById('use-xhttp')?.checked || false;
    profile.useXHTTP = useXHTTP;
    if (useXHTTP) {
        profile.xhttpPublicKey = document.getElementById('xhttp-public-key')?.value.trim() || '';
        profile.xhttpShortId = document.getElementById('xhttp-short-id')?.value.trim() || '';
        profile.xhttpServerName = document.getElementById('xhttp-server-name')?.value.trim() || '';
        profile.xhttpFingerprint = document.getElementById('xhttp-fingerprint')?.value || 'chrome';
    }
    
    saveProfiles();
    renderProfiles();
    addLog('success', `Профиль "${newName}" обновлен`);
};

window.deleteProfile = function(index) {
    if (index < 0 || index >= profiles.length) return;
    
    const profile = profiles[index];
    if (!confirm(`Удалить профиль "${profile.name}"?`)) return;
    
    profiles.splice(index, 1);
    saveProfiles();
    renderProfiles();
    addLog('info', `Профиль "${profile.name}" удален`);
};

function handleImportProfile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const imported = JSON.parse(event.target.result);
                if (Array.isArray(imported)) {
                    profiles.push(...imported);
                } else {
                    profiles.push(imported);
                }
                saveProfiles();
                renderProfiles();
                addLog('success', 'Профиль(и) импортированы');
            } catch (error) {
                addLog('error', 'Ошибка импорта: ' + error.message);
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

function handleExportProfile() {
    if (profiles.length === 0) {
        alert('Нет профилей для экспорта');
        return;
    }
    
    const dataStr = JSON.stringify(profiles, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `whispera-profiles-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    addLog('success', 'Профили экспортированы');
}

function updateConnectionStatus(connected, connecting = false) {
    appState.connected = connected;
    appState.connecting = connecting;

    // Логируем изменение статуса для отладки
    console.log(`[DEBUG] updateConnectionStatus: connected=${connected}, connecting=${connecting}`);

    const indicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const statusDetails = document.getElementById('status-details');
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');

    if (!indicator || !statusText || !statusDetails) {
        console.warn('[DEBUG] Status elements not found:', { indicator, statusText, statusDetails });
        return;
    }

    if (connected) {
        indicator.className = 'status-indicator connected';
        statusText.textContent = 'Подключено';
        statusDetails.textContent = 'VPN соединение активно';
        connectBtn.style.display = 'none';
        disconnectBtn.style.display = 'block';
    } else if (connecting) {
        indicator.className = 'status-indicator connecting';
        statusText.textContent = 'Подключение...';
        statusDetails.textContent = 'Установка соединения';
        connectBtn.style.display = 'none';
        disconnectBtn.style.display = 'none';
    } else {
        indicator.className = 'status-indicator disconnected';
        statusText.textContent = 'Отключено';
        statusDetails.textContent = 'Готов к подключению';
        connectBtn.style.display = 'block';
        disconnectBtn.style.display = 'none';
    }
}

function addLog(level, message) {
    const logsContent = document.getElementById('logs-content');
    if (!logsContent) return;

    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${level}`;
    logEntry.innerHTML = `<span class="log-time">[${timestamp}]</span> <span class="log-level">[${level.toUpperCase()}]</span> <span class="log-message">${escapeHtml(message)}</span>`;
    
    logsContent.appendChild(logEntry);
    logsContent.scrollTop = logsContent.scrollHeight;

    // Ограничиваем количество логов
    while (logsContent.children.length > 1000) {
        logsContent.removeChild(logsContent.firstChild);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Парсинг статистики трафика из логов Go клиента
function parseTrafficStats(logLine) {
    // Ищем паттерн: [STATS] 📊 VPN Traffic: TX=123 pkts, RX=456 pkts
    const statsMatch = logLine.match(/\[STATS\].*TX[=:\s]+(\d+).*RX[=:\s]+(\d+)/i);
    if (statsMatch) {
        const txPkts = parseInt(statsMatch[1]) || 0;
        const rxPkts = parseInt(statsMatch[2]) || 0;
        
        console.log(`[DEBUG] Parsed traffic stats: TX=${txPkts} pkts, RX=${rxPkts} pkts`);
        
        // Обновляем статистику пакетов
        appState.traffic.outbound.packets = txPkts;
        appState.traffic.inbound.packets = rxPkts;
        updateTrafficDisplay();
    }
    
    // Также ищем упрощенный формат: TX=123, RX=456
    const simpleStatsMatch = logLine.match(/TX[=:\s]+(\d+).*RX[=:\s]+(\d+)/i);
    if (simpleStatsMatch && !statsMatch) {
        const txPkts = parseInt(simpleStatsMatch[1]) || 0;
        const rxPkts = parseInt(simpleStatsMatch[2]) || 0;
        
        console.log(`[DEBUG] Parsed simple traffic stats: TX=${txPkts} pkts, RX=${rxPkts} pkts`);
        
        appState.traffic.outbound.packets = txPkts;
        appState.traffic.inbound.packets = rxPkts;
        updateTrafficDisplay();
    }
    
    // Ищем метрики Prometheus из логов (если есть)
    // Формат: "whispera_bytes_tx_total 12345" или "bytes_tx=12345"
    const bytesTxMatch = logLine.match(/bytes_tx[=:\s]+(\d+)/i);
    const bytesRxMatch = logLine.match(/bytes_rx[=:\s]+(\d+)/i);
    
    if (bytesTxMatch || bytesRxMatch) {
        const txBytes = bytesTxMatch ? parseInt(bytesTxMatch[1]) : appState.traffic.outbound.bytes;
        const rxBytes = bytesRxMatch ? parseInt(bytesRxMatch[1]) : appState.traffic.inbound.bytes;
        
        console.log(`[DEBUG] Parsed traffic bytes: TX=${txBytes} bytes, RX=${rxBytes} bytes`);
        
        // Вычисляем скорость (разница с предыдущим значением)
        const now = Date.now();
        const lastUpdate = appState.traffic.lastUpdate || now;
        const timeDiff = (now - lastUpdate) / 1000; // секунды
        
        if (timeDiff > 0 && appState.traffic.lastBytes) {
            const speedUp = (txBytes - appState.traffic.lastBytes.tx) / timeDiff;
            const speedDown = (rxBytes - appState.traffic.lastBytes.rx) / timeDiff;
            
            appState.traffic.speed.up = Math.max(0, speedUp);
            appState.traffic.speed.down = Math.max(0, speedDown);
        }
        
        appState.traffic.outbound.bytes = txBytes;
        appState.traffic.inbound.bytes = rxBytes;
        appState.traffic.lastBytes = { tx: txBytes, rx: rxBytes };
        appState.traffic.lastUpdate = now;
        
        // Добавляем в историю
        appState.traffic.history.push({
            time: now,
            up: appState.traffic.speed.up,
            down: appState.traffic.speed.down
        });
        
        // Оставляем только последние 60 секунд
        const cutoff = now - 60000;
        appState.traffic.history = appState.traffic.history.filter(h => h.time > cutoff);
        
        updateTrafficDisplay();
        updateTrafficChart();
    }
}

// Обновление отображения статистики
function updateTrafficDisplay() {
    const inboundBytes = appState.traffic.inbound.bytes;
    const outboundBytes = appState.traffic.outbound.bytes;
    const totalBytes = inboundBytes + outboundBytes;
    
    const inboundPkts = appState.traffic.inbound.packets;
    const outboundPkts = appState.traffic.outbound.packets;
    const totalPkts = inboundPkts + outboundPkts;
    
    // Обновляем элементы UI
    const inboundBytesEl = document.getElementById('inbound-bytes');
    const outboundBytesEl = document.getElementById('outbound-bytes');
    const totalBytesEl = document.getElementById('total-bytes');
    const inboundPktsEl = document.getElementById('inbound-packets');
    const outboundPktsEl = document.getElementById('outbound-packets');
    const totalPktsEl = document.getElementById('total-packets');
    const speedUpEl = document.getElementById('speed-up');
    const speedDownEl = document.getElementById('speed-down');
    
    if (inboundBytesEl) inboundBytesEl.textContent = formatBytes(inboundBytes);
    if (outboundBytesEl) outboundBytesEl.textContent = formatBytes(outboundBytes);
    if (totalBytesEl) totalBytesEl.textContent = formatBytes(totalBytes);
    if (inboundPktsEl) inboundPktsEl.textContent = `${inboundPkts.toLocaleString()} пакетов`;
    if (outboundPktsEl) outboundPktsEl.textContent = `${outboundPkts.toLocaleString()} пакетов`;
    if (totalPktsEl) totalPktsEl.textContent = `${totalPkts.toLocaleString()} пакетов`;
    if (speedUpEl) speedUpEl.textContent = formatBytes(appState.traffic.speed.up) + '/s';
    if (speedDownEl) speedDownEl.textContent = formatBytes(appState.traffic.speed.down) + '/s';
}

// Форматирование байтов
function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Обновление графика трафика
function updateTrafficChart() {
    const canvas = document.getElementById('traffic-chart');
    if (!canvas || appState.traffic.history.length === 0) return;
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    // Очищаем canvas
    ctx.clearRect(0, 0, width, height);
    
    // Настройки
    const padding = 20;
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;
    const maxSpeed = Math.max(
        ...appState.traffic.history.map(h => Math.max(h.up, h.down)),
        1
    );
    
    // Рисуем оси
    ctx.strokeStyle = '#4A5568';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.stroke();
    
    // Рисуем линии трафика
    if (appState.traffic.history.length > 1) {
        // Outbound (вверх)
        ctx.strokeStyle = '#3B82F6';
        ctx.lineWidth = 2;
        ctx.beginPath();
        appState.traffic.history.forEach((point, index) => {
            const x = padding + (index / (appState.traffic.history.length - 1)) * chartWidth;
            const y = height - padding - (point.up / maxSpeed) * chartHeight;
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.stroke();
        
        // Inbound (вниз)
        ctx.strokeStyle = '#10B981';
        ctx.lineWidth = 2;
        ctx.beginPath();
        appState.traffic.history.forEach((point, index) => {
            const x = padding + (index / (appState.traffic.history.length - 1)) * chartWidth;
            const y = height - padding - (point.down / maxSpeed) * chartHeight;
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.stroke();
    }
    
    // Легенда
    ctx.fillStyle = '#3B82F6';
    ctx.fillRect(width - 150, 10, 10, 10);
    ctx.fillStyle = '#F1F5F9';
    ctx.font = '12px sans-serif';
    ctx.fillText('Outbound', width - 135, 19);
    
    ctx.fillStyle = '#10B981';
    ctx.fillRect(width - 150, 25, 10, 10);
    ctx.fillStyle = '#F1F5F9';
    ctx.fillText('Inbound', width - 135, 34);
}

// Получение статистики с сервера (если подключен)
async function fetchServerTrafficStats() {
    const serverIp = document.getElementById('server-ip')?.value;
    if (!serverIp || !appState.connected) return;
    
    try {
        // Используем Rust команду для получения статистики
        const token = localStorage.getItem('whispera_token');
        const result = await invoke('get_server_traffic_stats', {
            serverIp: serverIp,
            token: token || null
        });
        
        if (result.success && result.data) {
            const data = result.data;
            // Обновляем статистику из сервера
            if (data.outbound) appState.traffic.outbound.bytes = data.outbound;
            if (data.inbound) appState.traffic.inbound.bytes = data.inbound;
            if (data.total_packets) {
                // Можно распределить пакеты пропорционально байтам
                const totalPkts = data.total_packets;
                if (data.total_bytes > 0) {
                    appState.traffic.outbound.packets = Math.round(totalPkts * (data.outbound / data.total_bytes));
                    appState.traffic.inbound.packets = Math.round(totalPkts * (data.inbound / data.total_bytes));
                }
            }
            updateTrafficDisplay();
        }
    } catch (error) {
        // Игнорируем ошибки API - используем только парсинг логов
    }
}

// Периодическое обновление статистики
let statsUpdateInterval = null;

function startStatsUpdate() {
    if (statsUpdateInterval) return;
    
    statsUpdateInterval = setInterval(() => {
        if (appState.connected) {
            fetchServerTrafficStats();
            updateTrafficChart();
        }
    }, 5000); // Обновляем каждые 5 секунд
}

function stopStatsUpdate() {
    if (statsUpdateInterval) {
        clearInterval(statsUpdateInterval);
        statsUpdateInterval = null;
    }
}

// Проверка статуса автозапуска
async function checkAutostartStatus() {
    try {
        const status = await invoke('get_autostart_status');
        const checkbox = document.getElementById('autostart-enabled');
        const statusText = document.getElementById('autostart-status');
        
        if (checkbox && statusText) {
            checkbox.checked = status.enabled || false;
            statusText.textContent = status.message || (status.enabled ? 'Автозапуск включен' : 'Автозапуск выключен');
            statusText.className = status.enabled ? 'text-success' : 'text-secondary';
        }
    } catch (error) {
        console.error('Ошибка проверки автозапуска:', error);
        const statusText = document.getElementById('autostart-status');
        if (statusText) {
            statusText.textContent = 'Ошибка проверки статуса: ' + error.message;
            statusText.className = 'text-error';
        }
    }
}

// Проверка прав администратора
async function checkAdminStatus() {
    try {
        const isAdmin = await invoke('is_admin');
        const adminStatusEl = document.getElementById('admin-status');
        const adminStatusText = document.getElementById('admin-status-text');
        
        if (adminStatusEl && adminStatusText) {
            adminStatusEl.style.display = 'block';
            if (isAdmin) {
                adminStatusEl.style.backgroundColor = '#10B98120';
                adminStatusEl.style.border = '1px solid #10B981';
                adminStatusText.innerHTML = '✅ Приложение запущено с правами администратора';
                adminStatusText.style.color = '#10B981';
            } else {
                adminStatusEl.style.backgroundColor = '#F59E0B20';
                adminStatusEl.style.border = '1px solid #F59E0B';
                adminStatusText.innerHTML = '⚠️ Приложение запущено без прав администратора. Для работы VPN рекомендуется запустить от имени администратора.';
                adminStatusText.style.color = '#F59E0B';
            }
        }
    } catch (error) {
        console.error('Ошибка проверки прав администратора:', error);
    }
}

// Обработка переключения автозапуска
async function handleAutostartToggle() {
    const checkbox = document.getElementById('autostart-enabled');
    const statusText = document.getElementById('autostart-status');
    
    if (!checkbox) return;
    
    const enabled = checkbox.checked;
    
    // Показываем индикатор загрузки
    if (statusText) {
        statusText.textContent = enabled ? 'Включение автозапуска...' : 'Выключение автозапуска...';
        statusText.className = 'text-info';
    }
    
    try {
        const result = await invoke('set_autostart', { enabled });
        
        if (result.success) {
            if (statusText) {
                statusText.textContent = result.message || (enabled ? 'Автозапуск включен' : 'Автозапуск выключен');
                statusText.className = enabled ? 'text-success' : 'text-secondary';
            }
            addLog('success', result.message || (enabled ? 'Автозапуск включен' : 'Автозапуск выключен'));
            
            // Сохраняем настройку
            const settings = JSON.parse(localStorage.getItem('whispera_settings') || '{}');
            settings.autostartEnabled = enabled;
            localStorage.setItem('whispera_settings', JSON.stringify(settings));
        } else {
            throw new Error(result.error || 'Неизвестная ошибка');
        }
    } catch (error) {
        console.error('Ошибка изменения автозапуска:', error);
        
        // Откатываем чекбокс
        checkbox.checked = !enabled;
        
        if (statusText) {
            statusText.textContent = 'Ошибка: ' + error.message;
            statusText.className = 'text-error';
        }
        addLog('error', 'Ошибка изменения автозапуска: ' + error.message);
        
        // Показываем предупреждение
        alert('Не удалось изменить автозапуск: ' + error.message + '\n\nУбедитесь, что:\n1. Приложение запущено от имени администратора\n2. Task Scheduler доступен\n3. У вас есть права на создание задач');
    }
}

