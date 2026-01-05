import { invoke } from '@tauri-apps/api/core';
import { appState } from './state.js';
import { updateTrafficDisplay } from './stats_ui.js';
import { updateTrafficChart } from './stats_chart.js';
import { waveAnimator } from './wave_animator.js';

// Track cumulative bytes for delta calculation
let lastInboundBytes = 0;
let lastOutboundBytes = 0;
let lastUpdateTime = Date.now();

export function parseTrafficStats(logLine) {
    const match = logLine.match(/TX[=:\s]+(\d+).*RX[=:\s]+(\d+)/i);
    if (match) {
        const outbound = parseInt(match[1]);
        const inbound = parseInt(match[2]);

        appState.traffic.outbound.packets = outbound;
        appState.traffic.inbound.packets = inbound;
        updateTrafficDisplay();

        // Update waves with packet-based data (estimate bytes)
        const now = Date.now();
        const timeDelta = (now - lastUpdateTime) / 1000; // seconds
        lastUpdateTime = now;

        if (timeDelta > 0) {
            // Estimate bytes per second (assuming ~1000 bytes per packet average)
            const downloadRate = (inbound - lastInboundBytes) * 1000 / timeDelta;
            const uploadRate = (outbound - lastOutboundBytes) * 1000 / timeDelta;

            if (waveAnimator && !isNaN(downloadRate) && !isNaN(uploadRate)) {
                waveAnimator.updateTraffic(
                    Math.max(0, downloadRate),
                    Math.max(0, uploadRate),
                    getProcessMemoryMB()
                );
            }
        }

        lastInboundBytes = inbound;
        lastOutboundBytes = outbound;
    }
}

export async function fetchServerTrafficStats() {
    const serverIp = document.getElementById('server-ip')?.value;
    if (!serverIp || !appState.connected) return;
    try {
        const result = await invoke('get_server_traffic_stats', { serverIp });
        if (result.success && result.data) {
            const now = Date.now();
            const timeDelta = (now - lastUpdateTime) / 1000;
            lastUpdateTime = now;

            const newInbound = result.data.inbound || 0;
            const newOutbound = result.data.outbound || 0;

            // Calculate bytes per second
            if (timeDelta > 0) {
                const downloadRate = (newInbound - appState.traffic.inbound.bytes) / timeDelta;
                const uploadRate = (newOutbound - appState.traffic.outbound.bytes) / timeDelta;

                if (waveAnimator) {
                    waveAnimator.updateTraffic(
                        Math.max(0, downloadRate),
                        Math.max(0, uploadRate),
                        getProcessMemoryMB()
                    );
                }
            }

            appState.traffic.outbound.bytes = newOutbound;
            appState.traffic.inbound.bytes = newInbound;
            updateTrafficDisplay();
        }
    } catch (e) { }
}

// Get memory usage (estimation for WebView process)
function getProcessMemoryMB() {
    if (performance.memory) {
        return performance.memory.usedJSHeapSize / (1024 * 1024);
    }
    // Fallback: estimate based on page activity
    return 50 + Math.random() * 30;
}

let statsInterval = null;
export function startStatsUpdate() {
    if (statsInterval) return;

    // Reset counters
    lastInboundBytes = 0;
    lastOutboundBytes = 0;
    lastUpdateTime = Date.now();

    // Disable simulation mode when connected
    if (waveAnimator) {
        waveAnimator.stopSimulation?.();
    }

    statsInterval = setInterval(() => {
        if (appState.connected) {
            fetchServerTrafficStats();
            updateTrafficChart();
        }
    }, 1000); // Update every second for smoother waves
}

export function stopStatsUpdate() {
    if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
    }

    // Re-enable simulation when disconnected
    if (waveAnimator && !appState.connected) {
        waveAnimator.simulateTraffic?.();
    }
}

