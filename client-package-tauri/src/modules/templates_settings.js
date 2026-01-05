export const settingsTemplate = `
    <h3>Настройки приложения</h3>
    <div class="settings-section">
        <h4>Автозапуск</h4>
        <div class="form-group">
            <label><input type="checkbox" id="autostart-enabled"> При входе в систему</label>
            <small id="autostart-status" class="text-secondary">Проверка...</small>
        </div>
        <div id="admin-status" class="admin-status" style="display: none;"><span id="admin-status-text"></span></div>
    </div>
    <div class="settings-section">
        <h4>Обфускация</h4>
        <div class="form-group"><label>Профиль</label>
            <select id="marionette-profile">
                <option value="browser">Browser</option>
                <option value="mobile">Mobile</option>
            </select>
        </div>
        <div class="form-group"><label><input type="checkbox" id="ai-evasion"> AI Evasion</label></div>
        <div class="form-group"><label><input type="checkbox" id="insecure-mode"> Insecure Mode</label></div>
        <div class="form-group"><label><input type="checkbox" id="auto-restart" checked> Auto Restart</label></div>
    </div>
    <button id="save-settings-btn" class="btn btn-primary">Сохранить</button>
`;
