export const homeTemplate = `
    <div class="status-card">
        <div class="status-indicator" id="status-indicator"></div>
        <div class="status-info">
            <h3 id="status-text">Отключено</h3>
            <p id="status-details">Готов к подключению</p>
        </div>
    </div>
    <div class="connection-form">
        <h3>Параметры подключения</h3>
        <div class="form-group"><label>IP сервера</label><input type="text" id="server-ip"></div>
        <div class="form-group"><label>Порт (UDP)</label><input type="number" id="server-port" value="51820"></div>
        <div class="form-group"><label>Публичный ключ</label>
            <div class="input-with-button">
                <input type="text" id="server-pub-key">
                <button id="fetch-key-btn" class="btn btn-small">Получить</button>
            </div>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="use-xhttp" onchange="toggleXHTTPFields()"> XHTTP+VLESS</label>
        </div>
        <div id="xhttp-fields" style="display: none; margin-left: 20px; border-left: 2px solid #3B82F6; padding-left: 15px;">
            <div class="form-group"><label>Public Key</label><input type="text" id="xhttp-public-key"></div>
            <div class="form-group"><label>Short ID</label><input type="text" id="xhttp-short-id"></div>
        </div>
        <div class="form-group"><label><input type="checkbox" id="proxy-mode"> SOCKS5</label></div>
    </div>
`;
