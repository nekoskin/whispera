import { profiles, saveProfiles } from './profiles_logic.js';
import { addLog } from './logs.js';
import { navigateTo } from './navigation.js';

export function renderProfiles() {
    const list = document.getElementById('profiles-list');
    if (!list) return;
    if (profiles.length === 0) {
        list.innerHTML = '<div class="profile-item empty"><p>Нет сохраненных профилей</p></div>';
        return;
    }
    list.innerHTML = profiles.map((p, i) => `
        <div class="profile-item">
            <div class="profile-info">
                <h4>${p.name || 'Без названия'}</h4>
                <p class="text-secondary">${p.serverIp}:${p.serverPort || 51820}</p>
            </div>
            <div class="profile-actions">
                <button class="btn btn-small btn-primary" onclick="applyProfile(${i})">Подключиться</button>
                <button class="btn btn-small btn-secondary" onclick="editProfile(${i})">Изменить</button>
                <button class="btn btn-small btn-danger" onclick="deleteProfile(${i})">Удалить</button>
            </div>
        </div>
    `).join('');
}

export function handleAddProfile() {
    const name = prompt('Введите название профиля:');
    if (!name) return;
    profiles.push({
        name,
        serverIp: document.getElementById('server-ip').value.trim(),
        serverPort: parseInt(document.getElementById('server-port').value) || 51820,
        serverPubKey: document.getElementById('server-pub-key').value.trim(),
    });
    saveProfiles(); renderProfiles();
    addLog('success', `Профиль "${name}" добавлен`);
}

window.applyProfile = (i) => {
    const p = profiles[i];
    if (!p) return;
    document.getElementById('server-ip').value = p.serverIp;
    document.getElementById('server-port').value = p.serverPort;
    document.getElementById('server-pub-key').value = p.serverPubKey;
    addLog('info', `Профиль "${p.name}" применен`);
    navigateTo('home');
};

window.editProfile = (i) => {
    const p = profiles[i];
    const newName = prompt('Новое название:', p.name);
    if (newName) { p.name = newName; saveProfiles(); renderProfiles(); }
};

window.deleteProfile = (i) => {
    if (confirm(`Удалить профиль "${profiles[i].name}"?`)) {
        profiles.splice(i, 1);
        saveProfiles(); renderProfiles();
    }
};
