import { listen } from '@tauri-apps/api/event';
import { appState } from './state.js';
import { addLog } from './logs.js';
import { updateConnectionStatus } from './connection_ui.js';
import { startStatsUpdate, stopStatsUpdate, parseTrafficStats } from './stats_logic.js';

export function setupGoClientListeners() {
    listen('go-client-output', (event) => {
        const data = event.payload;
        addLog('info', data);
        parseTrafficStats(data);
        if (checkConnected(data) && !appState.connected) {
            updateConnectedState();
        }
    });

    listen('go-client-error', (event) => {
        const data = event.payload;
        addLog('error', data);
        if (checkConnected(data) && !appState.connected) {
            updateConnectedState();
        }
    });

    listen('go-client-exit', (event) => {
        addLog('warning', `Go клиент завершился с кодом: ${event.payload}`);
        appState.connected = false;
        appState.connecting = false;
        updateConnectionStatus(false);
        stopStatsUpdate();
    });
}

function updateConnectedState() {
    appState.connected = true;
    appState.connecting = false;
    updateConnectionStatus(true);
    startStatsUpdate();
    addLog('success', 'Подключение установлено!');
}

function checkConnected(data) {
    const upper = data.toUpperCase();
    return upper.includes('VPN CONNECTION ESTABLISHED') ||
        upper.includes('HANDSHAKE SUCCESSFUL') ||
        upper.includes('READY TO ACCEPT CONNECTIONS') ||
        upper.includes('✅ WEBSOCKET');
}
