import { invoke } from '@tauri-apps/api/core';
import { addLog } from './logs.js';

export async function checkAutostartStatus() {
    try {
        const status = await invoke('get_autostart_status');
        const checkbox = document.getElementById('autostart-enabled');
        const statusText = document.getElementById('autostart-status');
        if (checkbox && statusText) {
            checkbox.checked = status.enabled || false;
            statusText.textContent = status.enabled ? 'Автозапуск включен' : 'Автозапуск выключен';
            statusText.className = status.enabled ? 'text-success' : 'text-secondary';
        }
    } catch (e) {
        console.error('Autostart check failed:', e);
    }
}

export async function checkAdminStatus() {
    try {
        const isAdmin = await invoke('is_admin');
        const el = document.getElementById('admin-status');
        const text = document.getElementById('admin-status-text');
        if (el && text) {
            el.style.display = 'block';
            el.style.backgroundColor = isAdmin ? '#10B98120' : '#EF444420';
            el.style.border = `1px solid ${isAdmin ? '#10B981' : '#EF4444'}`;
            text.innerHTML = isAdmin ? '✅ Приложение запущено с правами администратора' :
                '❌ ПРИЛОЖЕНИЕ ЗАПУЩЕНО БЕЗ ПРАВ АДМИНИСТРАТОРА. VPN НЕ БУДЕТ РАБОТАТЬ.';
            text.style.color = isAdmin ? '#10B981' : '#EF4444';
        }
    } catch (e) {
        console.error('Admin status check failed:', e);
    }
}

export async function handleAutostartToggle() {
    const checkbox = document.getElementById('autostart-enabled');
    if (!checkbox) return;
    const enabled = checkbox.checked;
    try {
        const result = await invoke('set_autostart', { enabled });
        if (result.success) {
            addLog('success', enabled ? 'Автозапуск включен' : 'Автозапуск выключен');
            checkAutostartStatus();
        }
    } catch (e) {
        checkbox.checked = !enabled;
        alert('Ошибка изменения автозапуска: ' + e.message);
    }
}
