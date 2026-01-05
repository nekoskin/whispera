import { addLog } from './logs.js';

const SETTINGS_KEY = 'whispera_settings_v2';

const DEFAULTS = {
    // General
    obfuscationMode: 'ML',
    mtu: '1300',
    dnsServer: '1.1.1.1',

    // Connectivity
    mixedPort: '9697',
    bindAddress: '127.0.0.1',
    tunStack: 'Mixed', // Mixed, gVisor, System
    dnsOverride: false,
    ipv6: true,

    // API
    apiSecret: 'NmkTcn3HS4JYzYC3',
    apiUrl: 'http://127.0.0.1:9686'
};

export function loadSettings() {
    let s = {};
    try {
        const saved = localStorage.getItem(SETTINGS_KEY);
        if (saved) s = JSON.parse(saved);
    } catch (e) { console.error(e); }

    const settings = { ...DEFAULTS, ...s };

    // Apply to UI
    // General
    setVal('obfuscation-mode', settings.obfuscationMode);
    setVal('mtu-value', settings.mtu);
    setVal('dns-server', settings.dnsServer);

    // Connectivity
    setText('mixed-port-display', settings.mixedPort);
    setText('bind-address-display', settings.bindAddress);
    setText('api-url', settings.apiUrl);
    setText('api-secret', settings.apiSecret);

    setChk('dns-override', settings.dnsOverride);
    setChk('ipv6-enabled', settings.ipv6);

    // Tun Stack logic
    const stackBtns = document.querySelectorAll('#tun-stack-control .segment-btn');
    stackBtns.forEach(btn => {
        if (btn.dataset.value === settings.tunStack) btn.classList.add('active');
        else btn.classList.remove('active');
    });

    return settings;
}

export function handleSaveSettings() {
    saveCurrentState();
    addLog('success', 'Настройки сохранены');
}

function saveCurrentState() {
    const s = {
        obfuscationMode: getVal('obfuscation-mode'),
        mtu: getVal('mtu-value'),
        dnsServer: getVal('dns-server'),

        mixedPort: getText('mixed-port-display'),
        bindAddress: getText('bind-address-display'),
        dnsOverride: getChk('dns-override'),
        ipv6: getChk('ipv6-enabled'),
        tunStack: document.querySelector('#tun-stack-control .segment-btn.active')?.dataset.value || 'Mixed',

        // Preserve API details (read-only for now)
        apiSecret: DEFAULTS.apiSecret,
        apiUrl: DEFAULTS.apiUrl
    };
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

// Helpers
function getText(id) { return document.getElementById(id)?.textContent?.trim() || ''; }
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function getChk(id) { return document.getElementById(id)?.checked || false; }
function setChk(id, val) { const el = document.getElementById(id); if (el) el.checked = val; }
function getVal(id) { return document.getElementById(id)?.value || ''; }
function setVal(id, val) { const el = document.getElementById(id); if (el) el.value = val; }


// Initialization of listeners
export function initSettingsLogic() {
    loadSettings();

    // General Settings Listeners (Auto-save)
    ['obfuscation-mode', 'mtu-value', 'dns-server'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', saveCurrentState);
            el.addEventListener('input', saveCurrentState); // Save while typing? Maybe debateable, but robust
        }
    });

    // Edit Mixed Port
    document.getElementById('edit-mixed-port')?.addEventListener('click', () => {
        const current = getText('mixed-port-display');
        const newVal = prompt('Введите смешанный порт:', current);
        if (newVal && newVal.trim() !== '') {
            setText('mixed-port-display', newVal.trim());
            saveCurrentState();
        }
    });

    // Edit Bind Address
    document.getElementById('edit-bind-address')?.addEventListener('click', () => {
        const current = getText('bind-address-display');
        const newVal = prompt('Введите адрес привязки:', current);
        if (newVal && newVal.trim() !== '') {
            setText('bind-address-display', newVal.trim());
            saveCurrentState();
        }
    });

    // Tun Stack Segment Control
    const stackBtns = document.querySelectorAll('#tun-stack-control .segment-btn');
    stackBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            stackBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            saveCurrentState();
        });
    });

    // Toggles Auto-save
    document.getElementById('dns-override')?.addEventListener('change', saveCurrentState);
    document.getElementById('ipv6-enabled')?.addEventListener('change', saveCurrentState);

    // Copy Buttons
    document.getElementById('copy-api')?.addEventListener('click', () => {
        const txt = getText('api-url');
        navigator.clipboard.writeText(txt).then(() => alert('API URL скопирован'));
    });

    document.getElementById('copy-secret')?.addEventListener('click', () => {
        const txt = getText('api-secret');
        navigator.clipboard.writeText(txt).then(() => alert('Secret скопирован'));
    });

    // Open Panel
    document.getElementById('open-panel')?.addEventListener('click', () => {
        const url = getText('api-url');
        window.open(url, '_blank');
    });
}

// Auto-run if imported
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSettingsLogic);
} else {
    initSettingsLogic();
}
