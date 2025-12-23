// Whispera Configuration Wizard - Мастер упрощенной настройки

class ConfigWizard {
    constructor() {
        this.step = 1;
        this.config = {
            server: {
                ip: '',
                port: 51820,
                tcpPort: 4443,
                wsPort: 8080,
                ws2Port: 8443
            },
            obfuscation: {
                profile: 'http2',
                autoProfile: true,
                marionetteProfile: 'browser'
            },
            user: {
                username: '',
                trafficLimit: 0,
                expiryDate: null
            }
        };
    }

    async init() {
        // Проверяем, нужна ли первоначальная настройка
        const needsSetup = await this.checkNeedsSetup();
        if (needsSetup) {
            await this.showWizard();
        }
    }

    async checkNeedsSetup() {
        try {
            const info = await api.getSystemInfo();
            // Если нет пользователей или сервер не настроен
            const users = await api.getUsers();
            return users.length === 0 || !info.server_pub;
        } catch {
            return true;
        }
    }

    async showWizard() {
        const wizardHTML = `
            <div id="setupWizard" class="setup-wizard">
                <div class="wizard-container">
                    <div class="wizard-header">
                        <h1><i class="fas fa-magic"></i> Мастер настройки Whispera</h1>
                        <p>Давайте настроим ваш VPN сервер за несколько простых шагов</p>
                    </div>
                    
                    <div class="wizard-progress">
                        <div class="progress-step ${this.step >= 1 ? 'active' : ''} ${this.step > 1 ? 'completed' : ''}">
                            <div class="step-number">1</div>
                            <div class="step-label">Сервер</div>
                        </div>
                        <div class="progress-line"></div>
                        <div class="progress-step ${this.step >= 2 ? 'active' : ''} ${this.step > 2 ? 'completed' : ''}">
                            <div class="step-number">2</div>
                            <div class="step-label">Обфускация</div>
                        </div>
                        <div class="progress-line"></div>
                        <div class="progress-step ${this.step >= 3 ? 'active' : ''} ${this.step > 3 ? 'completed' : ''}">
                            <div class="step-number">3</div>
                            <div class="step-label">Пользователь</div>
                        </div>
                        <div class="progress-line"></div>
                        <div class="progress-step ${this.step >= 4 ? 'active' : ''}">
                            <div class="step-number">4</div>
                            <div class="step-label">Готово</div>
                        </div>
                    </div>

                    <div class="wizard-content">
                        ${this.renderStep(this.step)}
                    </div>

                    <div class="wizard-footer">
                        ${this.step > 1 ? '<button class="btn btn-secondary" onclick="wizard.previousStep()">Назад</button>' : ''}
                        <button class="btn btn-primary" onclick="wizard.nextStep()">
                            ${this.step === 4 ? 'Завершить' : 'Далее'}
                            <i class="fas fa-arrow-right"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', wizardHTML);
        await this.loadStepData();
    }

    renderStep(step) {
        switch(step) {
            case 1:
                return this.renderServerStep();
            case 2:
                return this.renderObfuscationStep();
            case 3:
                return this.renderUserStep();
            case 4:
                return this.renderFinishStep();
            default:
                return '';
        }
    }

    renderServerStep() {
        return `
            <div class="wizard-step">
                <h2><i class="fas fa-server"></i> Настройка сервера</h2>
                <p class="step-description">Укажите основные параметры вашего сервера</p>
                
                <div class="form-group">
                    <label>
                        <i class="fas fa-network-wired"></i>
                        IP адрес сервера
                        <span class="tooltip" title="Автоматически определен из текущего подключения">
                            <i class="fas fa-info-circle"></i>
                        </span>
                    </label>
                    <input type="text" id="serverIP" class="form-control" 
                           placeholder="Автоматически определяется..." 
                           value="${this.config.server.ip}">
                    <small class="form-help">Оставьте пустым для автоматического определения</small>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label><i class="fas fa-ethernet"></i> UDP порт</label>
                        <input type="number" id="serverPort" class="form-control" 
                               value="${this.config.server.port}" min="1024" max="65535">
                    </div>
                    <div class="form-group">
                        <label><i class="fas fa-plug"></i> TCP порт</label>
                        <input type="number" id="tcpPort" class="form-control" 
                               value="${this.config.server.tcpPort}" min="1024" max="65535">
                    </div>
                </div>

                <div class="info-box">
                    <i class="fas fa-lightbulb"></i>
                    <strong>Рекомендация:</strong> Используйте стандартные порты для лучшей совместимости. 
                    Убедитесь, что порты открыты в файрволе.
                </div>
            </div>
        `;
    }

    renderObfuscationStep() {
        return `
            <div class="wizard-step">
                <h2><i class="fas fa-shield-alt"></i> Настройка обфускации</h2>
                <p class="step-description">Выберите профиль обфускации для обхода блокировок</p>
                
                <div class="form-group">
                    <label>
                        <i class="fas fa-code"></i>
                        Профиль обфускации
                    </label>
                    <select id="obfsProfile" class="form-control">
                        <option value="quic" ${this.config.obfuscation.profile === 'quic' ? 'selected' : ''}>
                            QUIC (Быстрый, рекомендуемый)
                        </option>
                        <option value="http2" ${this.config.obfuscation.profile === 'http2' ? 'selected' : ''}>
                            HTTP/2 (Стабильный)
                        </option>
                        <option value="websocket" ${this.config.obfuscation.profile === 'websocket' ? 'selected' : ''}>
                            WebSocket (Универсальный)
                        </option>
                    </select>
                    <small class="form-help">QUIC рекомендуется для большинства случаев</small>
                </div>

                <div class="form-group">
                    <label>
                        <i class="fas fa-user-secret"></i>
                        Marionette профиль
                    </label>
                    <select id="marionetteProfile" class="form-control">
                        <option value="browser" ${this.config.obfuscation.marionetteProfile === 'browser' ? 'selected' : ''}>
                            Browser (Универсальный)
                        </option>
                        <option value="vk">VKontakte</option>
                        <option value="yandex">Yandex</option>
                        <option value="mailru">Mail.ru</option>
                    </select>
                    <small class="form-help">Имитация популярных сервисов для обхода блокировок</small>
                </div>

                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="autoProfile" ${this.config.obfuscation.autoProfile ? 'checked' : ''}>
                        <span>Автоматический выбор профиля</span>
                    </label>
                    <small class="form-help">Система автоматически выберет лучший профиль для каждого подключения</small>
                </div>

                <div class="info-box info-success">
                    <i class="fas fa-check-circle"></i>
                    <strong>Автоматическая настройка:</strong> Система автоматически оптимизирует параметры 
                    для максимальной производительности и обхода блокировок.
                </div>
            </div>
        `;
    }

    renderUserStep() {
        return `
            <div class="wizard-step">
                <h2><i class="fas fa-user-plus"></i> Создание первого пользователя</h2>
                <p class="step-description">Создайте первого пользователя для подключения к VPN</p>
                
                <div class="form-group">
                    <label>
                        <i class="fas fa-user"></i>
                        Имя пользователя
                    </label>
                    <input type="text" id="username" class="form-control" 
                           placeholder="user1" required 
                           value="${this.config.user.username}">
                    <small class="form-help">Используйте латинские буквы и цифры</small>
                </div>

                <div class="form-group">
                    <label>
                        <i class="fas fa-envelope"></i>
                        Email (опционально)
                    </label>
                    <input type="email" id="userEmail" class="form-control" 
                           placeholder="user@example.com">
                </div>

                <div class="form-group">
                    <label>
                        <i class="fas fa-tachometer-alt"></i>
                        Лимит трафика (GB)
                    </label>
                    <input type="number" id="trafficLimit" class="form-control" 
                           value="${this.config.user.trafficLimit}" min="0" step="0.1">
                    <small class="form-help">0 = безлимит</small>
                </div>

                <div class="form-group">
                    <label>
                        <i class="fas fa-calendar"></i>
                        Срок действия (опционально)
                    </label>
                    <input type="date" id="expiryDate" class="form-control">
                    <small class="form-help">Оставьте пустым для бессрочного доступа</small>
                </div>

                <div class="info-box">
                    <i class="fas fa-key"></i>
                    <strong>Безопасность:</strong> Ключи шифрования будут сгенерированы автоматически. 
                    Вы сможете скачать конфигурацию клиента после создания пользователя.
                </div>
            </div>
        `;
    }

    renderFinishStep() {
        return `
            <div class="wizard-step">
                <div class="finish-step-content">
                    <div class="success-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h2>Настройка завершена!</h2>
                    <p>Ваш Whispera VPN сервер готов к использованию</p>
                    
                    <div class="summary-box">
                        <h3><i class="fas fa-list"></i> Сводка настроек:</h3>
                        <ul class="summary-list">
                            <li><strong>Сервер:</strong> ${this.config.server.ip || 'Автоматически определен'}:${this.config.server.port}</li>
                            <li><strong>Профиль обфускации:</strong> ${this.config.obfuscation.profile}</li>
                            <li><strong>Marionette:</strong> ${this.config.obfuscation.marionetteProfile}</li>
                            <li><strong>Пользователь:</strong> ${this.config.user.username}</li>
                        </ul>
                    </div>

                    <div class="next-steps">
                        <h3><i class="fas fa-rocket"></i> Следующие шаги:</h3>
                        <ol>
                            <li>Скачайте конфигурацию клиента для пользователя "${this.config.user.username}"</li>
                            <li>Установите Whispera клиент на ваше устройство</li>
                            <li>Импортируйте конфигурацию и подключитесь</li>
                        </ol>
                    </div>
                </div>
            </div>
        `;
    }

    async loadStepData() {
        if (this.step === 1) {
            // Автоматическое определение IP адреса
            try {
                const info = await api.getSystemInfo();
                const hostname = window.location.hostname;
                if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1') {
                    this.config.server.ip = hostname;
                    const ipInput = document.querySelector('#setupWizard #serverIP');
                    if (ipInput) ipInput.value = hostname;
                }
            } catch (e) {
                console.log('Не удалось определить IP автоматически');
            }
        }
    }

    async nextStep() {
        // Валидация текущего шага
        if (!this.validateStep(this.step)) {
            return;
        }

        // Сохранение данных текущего шага
        this.saveStepData(this.step);

        if (this.step < 4) {
            this.step++;
            this.updateWizard();
        } else {
            // Завершение настройки
            await this.finishSetup();
        }
    }

    previousStep() {
        if (this.step > 1) {
            this.step--;
            this.updateWizard();
        }
    }

    validateStep(step) {
        const scope = (sel) => document.querySelector(`#setupWizard ${sel}`);
        switch(step) {
            case 1:
                const port = parseInt(scope('#serverPort')?.value);
                return port && port >= 1024 && port <= 65535;
            case 2:
                return true; // Все опционально
            case 3:
                const username = scope('#username')?.value.trim();
                return username && /^[a-zA-Z0-9_-]+$/.test(username);
            default:
                return true;
        }
    }

    saveStepData(step) {
        const scope = (sel) => document.querySelector(`#setupWizard ${sel}`);
        switch(step) {
            case 1:
                this.config.server.ip = scope('#serverIP')?.value || '';
                this.config.server.port = parseInt(scope('#serverPort')?.value) || 51820;
                this.config.server.tcpPort = parseInt(scope('#tcpPort')?.value) || 4443;
                break;
            case 2:
                this.config.obfuscation.profile = scope('#obfsProfile')?.value || 'http2';
                this.config.obfuscation.marionetteProfile = scope('#marionetteProfile')?.value || 'browser';
                this.config.obfuscation.autoProfile = scope('#autoProfile')?.checked || false;
                break;
            case 3:
                this.config.user.username = scope('#username')?.value.trim() || '';
                this.config.user.email = scope('#userEmail')?.value || null;
                this.config.user.trafficLimit = parseFloat(scope('#trafficLimit')?.value) || 0;
                this.config.user.expiryDate = scope('#expiryDate')?.value || null;
                break;
        }
    }

    updateWizard() {
        const content = document.querySelector('.wizard-content');
        if (content) {
            content.innerHTML = this.renderStep(this.step);
        }

        // Обновляем прогресс
        document.querySelectorAll('.progress-step').forEach((step, index) => {
            step.classList.remove('active', 'completed');
            if (index + 1 < this.step) {
                step.classList.add('completed');
            } else if (index + 1 === this.step) {
                step.classList.add('active');
            }
        });

        // Обновляем кнопки
        const footer = document.querySelector('.wizard-footer');
        if (footer) {
            footer.innerHTML = `
                ${this.step > 1 ? '<button class="btn btn-secondary" onclick="wizard.previousStep()">Назад</button>' : ''}
                <button class="btn btn-primary" onclick="wizard.nextStep()">
                    ${this.step === 4 ? 'Завершить' : 'Далее'}
                    <i class="fas fa-arrow-right"></i>
                </button>
            `;
        }

        this.loadStepData();
    }

    async finishSetup() {
        try {
            // Генерируем ключи для пользователя
            let keys = null;
            try {
                keys = await api.generateKeys();
            } catch (apiError) {
                // Если API недоступен, генерируем на клиенте
                console.log('API недоступен, генерируем ключи на клиенте');
                if (window.app && typeof window.app.generateKeysClientSide === 'function') {
                    keys = await window.app.generateKeysClientSide();
                } else {
                    // Fallback генерация
                    const privateKeyBytes = new Uint8Array(32);
                    crypto.getRandomValues(privateKeyBytes);
                    const privateKey = Array.from(privateKeyBytes)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');
                    
                    // Для публичного ключа нужна криптография, но для начала используем заглушку
                    // В реальности нужно использовать Web Crypto API для x25519
                    keys = {
                        privateKey: privateKey,
                        publicKey: null // Будет вычислен на сервере
                    };
                }
            }

            // Создаем пользователя с настройками
            const genId = () => 'u_' + Date.now().toString(36);
            const genUUIDv4 = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
                const r = Math.random()*16|0, v = c === 'x' ? r : (r&0x3|0x8);
                return v.toString(16);
            });

            const userData = {
                id: genId(),
                uuid: genUUIDv4(),
                username: this.config.user.username,
                email: this.config.user.email,
                trafficLimit: this.config.user.trafficLimit,
                expiryDate: this.config.user.expiryDate,
                obfsProfile: this.config.obfuscation.profile,
                marionetteProfile: this.config.obfuscation.marionetteProfile,
                autoProfile: this.config.obfuscation.autoProfile,
                russianService: 'vk',
                appProfile: 'browser',
                // КРИТИЧНО: Добавляем приватный ключ для Quick Connect
                privateKey: keys?.privateKey ? keys.privateKey.trim() : '',
                publicKey: keys?.publicKey ? keys.publicKey.trim() : null
            };

            await api.addUser(userData);
            
            // Сохраняем конфигурацию сервера
            await this.saveServerConfig();

            // Закрываем мастер
            setTimeout(() => {
                document.getElementById('setupWizard')?.remove();
                // Перезагружаем приложение
                if (window.app) {
                    window.app.loadUsers();
                    window.app.navigateTo('users');
                }
            }, 2000);

            this.showSuccessMessage('Настройка завершена успешно!');
        } catch (error) {
            alert('Ошибка при завершении настройки: ' + error.message);
        }
    }

    async saveServerConfig() {
        try {
            // Сохраняем конфигурацию через API
            const config = {
                server: {
                    ip: this.config.server.ip,
                    port: this.config.server.port,
                    tcpPort: this.config.server.tcpPort
                },
                obfuscation: this.config.obfuscation
            };
            
            // Можно добавить API endpoint для сохранения конфигурации
            // await api.updateConfig(config);
        } catch (error) {
            console.error('Ошибка сохранения конфигурации:', error);
        }
    }

    showSuccessMessage(message) {
        const toast = document.createElement('div');
        toast.className = 'toast toast-success';
        toast.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}

// Глобальный экземпляр
let wizard;

