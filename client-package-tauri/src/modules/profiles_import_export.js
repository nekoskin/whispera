import { profiles, saveProfiles } from './profiles_logic.js';
import { renderProfiles } from './profiles_ui.js';
import { addLog } from './logs.js';

export function handleImportProfile() {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = '.json';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const imported = JSON.parse(event.target.result);
                if (Array.isArray(imported)) profiles.push(...imported);
                else profiles.push(imported);
                saveProfiles(); renderProfiles();
                addLog('success', 'Профиль(и) импортированы');
            } catch (err) { addLog('error', 'Ошибка импорта: ' + err.message); }
        };
        reader.readAsText(file);
    };
    input.click();
}

export function handleExportProfile() {
    if (profiles.length === 0) { alert('Нет профилей для экспорта'); return; }
    const blob = new Blob([JSON.stringify(profiles, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `whispera-profiles-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    addLog('success', 'Профили экспортированы');
}
