export function addLog(level, message) {
    const logsContent = document.getElementById('logs-content');
    if (!logsContent) return;

    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry log-${level}`;
    logEntry.innerHTML = `
        <span class="log-time">[${timestamp}]</span> 
        <span class="log-level">[${level.toUpperCase()}]</span> 
        <span class="log-message">${escapeHtml(message)}</span>
    `;

    logsContent.appendChild(logEntry);
    logsContent.scrollTop = logsContent.scrollHeight;

    while (logsContent.children.length > 1000) {
        logsContent.removeChild(logsContent.firstChild);
    }
}

export function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
