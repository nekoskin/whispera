// Whispera Client Entry Point
import { invoke } from '@tauri-apps/api/core';
import { initI18n } from './modules/i18n.js';
import { appState } from './modules/state.js';
import { addLog } from './modules/logs.js';
import { navigateTo, initNavigation } from './modules/navigation.js';
import { handleFetchServerKey } from './modules/api_key.js';
import { handleQuickConnect } from './modules/api_config.js';
import { setupGoClientListeners } from './modules/go_client_listeners.js';
import { handleConnect, handleDisconnect } from './modules/connection_logic.js';
import { loadSettings, handleSaveSettings } from './modules/settings_logic.js';
import { loadProfiles } from './modules/profiles_logic.js';
import { handleAddProfile, renderProfiles } from './modules/profiles_ui.js';
import { handleImportProfile, handleExportProfile } from './modules/profiles_import_export.js';
import { checkAutostartStatus, checkAdminStatus, handleAutostartToggle } from './modules/system_status.js';
import { waveAnimator } from './modules/wave_animator.js';

// Features imports
import { initNotifications } from './modules/notifications.js';
import { activeConnectionManager } from './modules/active_connections.js';
import './modules/dashboard_data.js'; // Auto-initializes IP info, system info, and site pings
import './modules/settings_persistence.js'; // Auto-initializes settings persistence

document.addEventListener('DOMContentLoaded', initializeApp);

async function initializeApp() {
    initI18n();
    console.log('[App] Initializing...');

    try {
        appState.goClientPath = await invoke('get_go_client_path');
        addLog('info', appState.goClientPath ? `Client found: ${appState.goClientPath}` : 'Client not found');
    } catch (e) { addLog('error', `Init error: ${e.message}`); }

    loadSettings();
    loadProfiles();
    checkAutostartStatus();
    checkAdminStatus();
    setupEventHandlers();
    setupGoClientListeners();
    renderProfiles();

    // Initialize UI features
    initNavigation();
    initNotifications();
}

function bind(id, event, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
}

function setupEventHandlers() {
    bind('connect-btn', 'click', handleConnect);
    bind('disconnect-btn', 'click', handleDisconnect);
    bind('fetch-key-btn', 'click', () => handleFetchServerKey());
    bind('quick-connect-btn', 'click', handleQuickConnect);
    bind('save-settings-btn', 'click', handleSaveSettings);
    bind('add-profile-btn', 'click', handleAddProfile);
    bind('import-profile-btn', 'click', handleImportProfile);
    bind('export-profile-btn', 'click', handleExportProfile);
    bind('autostart-enabled', 'change', handleAutostartToggle);
    bind('clear-logs-btn', 'click', () => {
        const logs = document.getElementById('logs-content');
        if (logs) logs.innerHTML = '';
    });

    // Connections Page Handlers - Handled by ActiveConnectionManager
    bind('close-all-btn', 'click', () => activeConnectionManager.closeAll());
    bind('connections-filter', 'input', (e) => activeConnectionManager.filterConnections(e.target.value));

    // Logo -> Home
    const logo = document.querySelector('.logo-avatar');
    if (logo) {
        logo.style.cursor = 'pointer';
        logo.addEventListener('click', () => {
            document.querySelectorAll('.nav-icon-btn').forEach(b => b.classList.remove('active'));
            navigateTo('home');
        });
    }

    // Profile Card -> Settings
    bind('profile-settings-btn', 'click', () => {
        document.querySelectorAll('.nav-icon-btn').forEach(b => b.classList.remove('active'));
        const s = document.querySelector('.nav-icon-btn[data-page="settings"]');
        if (s) s.classList.add('active');
        navigateTo('settings');
    });

    // Navigation (Prizrak-Box style)
    document.querySelectorAll('.nav-icon-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.nav-icon-btn').forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            navigateTo(e.currentTarget.dataset.page);
        });
    });

    document.querySelectorAll('.stat-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => navigateTo(e.currentTarget.dataset.page));
    });

    // Mode tabs
    document.querySelectorAll('.mode-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
            e.currentTarget.classList.add('active');
            appState.mode = e.currentTarget.dataset.mode;
        });
    });

    // Toggle switches
    bind('proxy-toggle', 'change', (e) => { appState.proxyEnabled = e.target.checked; });
    bind('tun-toggle', 'change', (e) => { appState.tunEnabled = e.target.checked; });
}
