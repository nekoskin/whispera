import { appState } from './state.js';

export function updateConnectionStatus(connected, connecting = false) {
    appState.connected = connected;
    appState.connecting = connecting;

    const ind = document.getElementById('status-indicator');
    const txt = document.getElementById('status-text');
    const det = document.getElementById('status-details');
    const cBt = document.getElementById('connect-btn');
    const dBt = document.getElementById('disconnect-btn');

    if (!ind || !txt) return;

    if (connected) {
        ind.className = 'status-indicator connected';
        txt.textContent = 'Подключено';
        det.textContent = 'VPN соединение активно';
        cBt.style.display = 'none';
        dBt.style.display = 'block';
    } else if (connecting) {
        ind.className = 'status-indicator connecting';
        txt.textContent = 'Подключение...';
        det.textContent = 'Установка соединения';
        cBt.style.display = 'none';
        dBt.style.display = 'none';
    } else {
        ind.className = 'status-indicator disconnected';
        txt.textContent = 'Отключено';
        det.textContent = 'Готов к подключению';
        cBt.style.display = 'block';
        dBt.style.display = 'none';
    }
}
