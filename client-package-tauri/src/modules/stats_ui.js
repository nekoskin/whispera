import { appState } from './state.js';

export function updateTrafficDisplay() {
    const inbound = appState.traffic.inbound.bytes;
    const outbound = appState.traffic.outbound.bytes;

    setTxt('inbound-bytes', formatBytes(inbound));
    setTxt('outbound-bytes', formatBytes(outbound));
    setTxt('total-bytes', formatBytes(inbound + outbound));
    setTxt('speed-up', formatBytes(appState.traffic.speed.up) + '/s');
    setTxt('speed-down', formatBytes(appState.traffic.speed.down) + '/s');
}

export function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function setTxt(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}
