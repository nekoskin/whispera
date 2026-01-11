const connectBtn = document.getElementById('connectBtn');
const connectionKeyInput = document.getElementById('connectionKey');
const statusIndicator = document.getElementById('statusIndicator');
const statusDot = document.querySelector('.status-dot');
const statusText = document.querySelector('.status-text');
const btnText = document.getElementById('btnText');
const btnIcon = document.querySelector('.btn-content i');
const loader = document.querySelector('.loader');

let isConnected = false;
let isConnecting = false;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Check if we have a stored key
    const storedKey = localStorage.getItem('whispera_key');
    if (storedKey) {
        connectionKeyInput.value = storedKey;
    }
});

connectBtn.addEventListener('click', async () => {
    if (isConnecting) return;

    if (isConnected) {
        // Disconnect logic
        updateStatus('disconnected');
        try {
            if (window.__TAURI__) {
                await window.__TAURI__.invoke('disconnect');
            }
        } catch (e) {
            console.error("Failed to disconnect:", e);
        }
        return;
    }

    const key = connectionKeyInput.value.trim();
    if (!key) {
        shakeInput();
        return;
    }

    // Start connection process
    updateStatus('connecting');

    try {
        if (window.__TAURI__) {
            await window.__TAURI__.invoke('connect', { key });
            updateStatus('connected');
            localStorage.setItem('whispera_key', key);
        } else {
            // Fallback for browser testing (mock)
            console.log('Tauri not found, simulating connection');
            setTimeout(() => {
                if (key.startsWith('whispera://')) {
                    updateStatus('connected');
                    localStorage.setItem('whispera_key', key);
                } else {
                    updateStatus('error');
                    setTimeout(() => updateStatus('disconnected'), 2000);
                }
            }, 2000);
        }
    } catch (e) {
        console.error(e);
        updateStatus('error');
    }
});

function updateStatus(status) {
    statusIndicator.className = 'status-indicator'; // reset

    switch (status) {
        case 'connecting':
            isConnecting = true;
            statusIndicator.classList.add('status-connecting');
            statusText.textContent = 'Connecting...';
            setBtnLoading(true);
            connectionKeyInput.disabled = true;
            break;

        case 'connected':
            isConnecting = false;
            isConnected = true;
            statusIndicator.classList.add('status-connected');
            statusText.textContent = 'Connected';
            setBtnLoading(false);

            btnText.textContent = 'Disconnect';
            btnIcon.className = 'fas fa-stop';
            connectBtn.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
            break;

        case 'disconnected':
            isConnecting = false;
            isConnected = false;
            statusText.textContent = 'Disconnected';
            setBtnLoading(false);
            connectionKeyInput.disabled = false;

            btnText.textContent = 'Connect';
            btnIcon.className = 'fas fa-power-off';
            connectBtn.style.background = ''; // reset to CSS default
            break;

        case 'error':
            isConnecting = false;
            isConnected = false;
            statusText.textContent = 'Connection Failed';
            statusText.style.color = '#ef4444';
            statusDot.style.backgroundColor = '#ef4444';
            setBtnLoading(false);
            connectionKeyInput.disabled = false;
            shakeInput();
            break;
    }
}

function setBtnLoading(loading) {
    const content = document.querySelector('.btn-content');
    if (loading) {
        content.style.display = 'none';
        loader.style.display = 'block';
    } else {
        content.style.display = 'flex';
        loader.style.display = 'none';
    }
}

function shakeInput() {
    connectionKeyInput.style.animation = 'shake 0.5s';
    connectionKeyInput.style.borderColor = '#ef4444';
    setTimeout(() => {
        connectionKeyInput.style.animation = '';
        connectionKeyInput.style.borderColor = '';
    }, 500);
}

// Add shake animation style dynamically
const style = document.createElement('style');
style.innerHTML = `
@keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-10px); }
    75% { transform: translateX(10px); }
}`;
document.head.appendChild(style);
