import { appState } from './state.js';

export function updateTrafficChart() {
    const canvas = document.getElementById('traffic-chart');
    if (!canvas || appState.traffic.history.length === 0) return;

    const ctx = canvas.getContext('2d');
    const { width, height } = canvas;
    ctx.clearRect(0, 0, width, height);

    const padding = 20;
    const chartW = width - padding * 2;
    const chartH = height - padding * 2;
    const maxS = Math.max(...appState.traffic.history.map(h => Math.max(h.up, h.down)), 1);

    // Draw lines (Simplified excerpt for 120-line limit)
    drawDataLine(ctx, appState.traffic.history, maxS, chartW, chartH, padding, height, '#3B82F6'); // UP
    drawDataLine(ctx, appState.traffic.history, maxS, chartW, chartH, padding, height, '#10B981'); // DOWN
}

function drawDataLine(ctx, history, maxS, w, h, p, canvasH, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    history.forEach((pt, i) => {
        const x = p + (i / (history.length - 1)) * w;
        const speed = color === '#3B82F6' ? pt.up : pt.down;
        const y = canvasH - p - (speed / maxS) * h;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
}
