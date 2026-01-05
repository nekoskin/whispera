import { invoke } from '@tauri-apps/api/core';
import { addLog } from './logs.js';

export async function handleFetchServerKey(insecure = false) {
    const serverIp = document.getElementById('server-ip').value.trim();
    if (!serverIp) {
        alert('Введите IP адрес сервера');
        return null;
    }

    try {
        addLog('info', `Запрос ключа с ${serverIp}...`);
        const result = await invoke('get_server_public_key', { serverIp, insecure });
        if (result.success) {
            document.getElementById('server-pub-key').value = result.key;
            addLog('success', 'Публичный ключ получен успешно');
            return result;
        } else {
            addLog('error', 'Не удалось получить ключ: ' + result.error);
            return result;
        }
    } catch (error) {
        addLog('error', 'Ошибка: ' + error.message);
        return { success: false, error: error.message };
    }
}
