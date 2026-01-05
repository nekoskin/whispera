import { invoke } from '@tauri-apps/api/core';
import { appState } from './state.js';
import { addLog } from './logs.js';
import { updateConnectionStatus } from './connection_ui.js';
import { startStatsUpdate, stopStatsUpdate } from './stats_logic.js';
import { handleFetchServerKey } from './api_key.js';

export async function handleConnect() {
    if (appState.connected || appState.connecting) {
        addLog('info', 'Остановка предыдущего подключения...');
        await handleDisconnect();
        await new Promise(r => setTimeout(r, 1000));
    }

    const config = gatherConfigFromUI();
    if (!config.server_ip) { alert('Введите IP адрес сервера'); return; }

    if (!config.xhttp_public_key && !config.server_public_key) {
        const keyResult = await handleFetchServerKey(config.insecure);
        if (keyResult?.success) config.server_public_key = keyResult.key;
        else { alert('Не удалось получить ключ сервера'); return; }
    }

    saveLastConnection(config);
    appState.connecting = true;
    updateConnectionStatus(false, true);

    try {
        const result = await invoke('start_go_client', { config });
        if (result.success) {
            addLog('success', `Go клиент запущен (PID: ${result.pid})`);
            setupConnectionMonitoring(result.pid);
        } else {
            appState.connecting = false;
            updateConnectionStatus(false);
            addLog('error', 'Ошибка: ' + result.error);
        }
    } catch (e) {
        addLog('error', 'Ошибка: ' + (e.message || e));
        appState.connecting = false;
        updateConnectionStatus(false);
    }
}

export async function handleDisconnect() {
    try {
        const result = await invoke('stop_go_client');
        appState.connected = false;
        appState.connecting = false;
        updateConnectionStatus(false);
        stopStatsUpdate();
        addLog('info', 'Соединение остановлено');
    } catch (e) {
        console.error('Disconnect failed:', e);
    }
}

function gatherConfigFromUI() {
    const port = parseInt(document.getElementById('server-port').value) || 51820;
    const useXHTTP = document.getElementById('use-xhttp')?.checked || false;
    return {
        server_ip: document.getElementById('server-ip').value.trim(),
        server_port: port,
        server_public_key: document.getElementById('server-pub-key').value.trim() || null,
        proxy_mode: document.getElementById('proxy-mode').checked,
        auto_profile: document.getElementById('auto-profile')?.checked || false,
        monitoring: true,
        app_profile: document.getElementById('marionette-profile')?.value || 'browser',
        xhttp_public_key: useXHTTP ? document.getElementById('xhttp-public-key')?.value.trim() : null,
        xhttp_short_id: useXHTTP ? document.getElementById('xhttp-short-id')?.value.trim() : null,
        xhttp_server_name: useXHTTP ? document.getElementById('xhttp-server-name')?.value.trim() : null,
        xhttp_fingerprint: useXHTTP ? document.getElementById('xhttp-fingerprint')?.value : null,
        insecure: document.getElementById('insecure-mode')?.checked || false,
        auto_restart: document.getElementById('auto-restart')?.checked || false,
    };
}

function saveLastConnection(c) {
    localStorage.setItem('whispera_last_connection', JSON.stringify(c));
}

function setupConnectionMonitoring(pid) {
    setTimeout(async () => {
        const check = await invoke('check_go_client_process', { pid });
        if (!check?.running && appState.connecting) {
            appState.connecting = false;
            updateConnectionStatus(false);
            addLog('error', 'Процесс клиента упал после запуска');
        }
    }, 2000);
}
