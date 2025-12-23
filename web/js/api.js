// Whispera API Client (аналогично 3x-ui)

class WhisperaAPI {
    constructor() {
        // Определяем API URL (по умолчанию используется порт 8081)
        this.baseURL = window.location.origin.includes('8081') 
            ? window.location.origin 
            : `${window.location.protocol}//${window.location.hostname}:8081`;
        
        this.token = localStorage.getItem('whispera_token') || null;
    }

    // Установка токена авторизации
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('whispera_token', token);
        } else {
            localStorage.removeItem('whispera_token');
        }
    }

    // Выполнение запроса к API
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            if (response.status === 401) {
                // Не авторизован - редирект на логин
                this.setToken(null);
                window.location.reload();
                throw new Error('Unauthorized');
            }

            // Проверяем Content-Type перед парсингом JSON
            const contentType = response.headers.get('content-type');
            let data;
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                // Если ответ не JSON, читаем как текст
                const text = await response.text();
                throw new Error(text || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            if (!response.ok) {
                // Извлекаем сообщение об ошибке
                const errorMsg = data.error || data.message || `HTTP ${response.status}: ${response.statusText}`;
                const error = new Error(errorMsg);
                error.status = response.status;
                error.data = data;
                throw error;
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Авторизация
    async login(username, password) {
        const response = await this.request('/api/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (response.token) {
            this.setToken(response.token);
        }
        
        return response;
    }

    // Выход
    logout() {
        this.setToken(null);
    }

    // System API
    async getSystemInfo() {
        return this.request('/api/system/info');
    }

    async getSystemStatus() {
        return this.request('/api/system/status');
    }

    async reloadConfig() {
        return this.request('/api/system/reload', { method: 'POST' });
    }

    // Users API
    async getUsers() {
        return this.request('/api/users');
    }

    async getUser(id) {
        return this.request(`/api/users/${id}`);
    }

    async addUser(userData) {
        return this.request('/api/users/add', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async updateUser(id, userData) {
        return this.request(`/api/users/${id}`, {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
    }

    async deleteUser(id) {
        return this.request('/api/users/delete', {
            method: 'POST',
            body: JSON.stringify({ id: id })
        });
    }

    async resetUserTraffic(id) {
        return this.request(`/api/users/${id}/reset-traffic`, {
            method: 'POST'
        });
    }

    // Sessions API
    async getSessions() {
        return this.request('/api/sessions');
    }

    async getSession(id) {
        return this.request(`/api/sessions/${id}`);
    }

    async killSession(id) {
        return this.request(`/api/sessions/${id}/kill`, {
            method: 'POST'
        });
    }

    // Stats API
    async getStats() {
        return this.request('/api/stats');
    }

    async getTrafficStats() {
        return this.request('/api/stats/traffic');
    }

    // Logs API
    async getLogs(limit = 100) {
        return this.request(`/api/logs?limit=${limit}`);
    }

    // Health check
    async healthCheck() {
        try {
            return await this.request('/health');
        } catch {
            return { status: 'unavailable' };
        }
    }

    // Keys API - генерация ключей
    async generateKeys() {
        return this.request('/api/keys/generate', {
            method: 'POST'
        });
    }

    async generateServerKeys() {
        return this.request('/api/keys/generate-server', {
            method: 'POST'
        });
    }

    // Certificate management API
    async getCertificateStatus() {
        return this.request('/api/certificate/status', {
            method: 'GET'
        });
    }

    async obtainCertificate(domain, email) {
        return this.request('/api/certificate/obtain', {
            method: 'POST',
            body: JSON.stringify({ domain, email })
        });
    }

    async renewCertificate() {
        return this.request('/api/certificate/renew', {
            method: 'POST'
        });
    }

    async derivePublicKey(privateKey) {
        return this.request('/api/keys/derive', {
            method: 'POST',
            body: JSON.stringify({ privateKey })
        });
    }

    // Firewall API
    async getFirewallRules() {
        return this.request('/api/firewall/rules');
    }

    async addFirewallRule(rule) {
        return this.request('/api/firewall/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async removeFirewallRule(ruleId) {
        return this.request('/api/firewall/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    async configureFirewall(ports) {
        return this.request('/api/firewall/configure', {
            method: 'POST',
            body: JSON.stringify({ ports })
        });
    }

    // Ports API
    async getPorts() {
        return this.request('/api/ports');
    }

    async addPort(portInfo) {
        return this.request('/api/ports/add', {
            method: 'POST',
            body: JSON.stringify(portInfo)
        });
    }

    async removePort(port) {
        return this.request('/api/ports/delete', {
            method: 'POST',
            body: JSON.stringify({ port })
        });
    }

    // Traffic API
    async getUserTraffic(userId) {
        return this.request(`/api/stats/user/${userId}`);
    }

    async getTrafficHistory(period = '24h') {
        return this.request(`/api/stats/traffic/history?period=${period}`);
    }

    // Ports validation API
    async checkPortAvailability(port, protocol = 'tcp') {
        return this.request(`/api/ports/check?port=${port}&protocol=${protocol}`);
    }

    async getUsedPorts() {
        return this.request('/api/ports/used');
    }

    // AdBlocker API
    async getAdblockStats() {
        return this.request('/api/adblock/stats');
    }

    async getAdblockRules() {
        return this.request('/api/adblock/rules');
    }

    async addAdblockRule(rule) {
        return this.request('/api/adblock/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async removeAdblockRule(ruleId) {
        return this.request('/api/adblock/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    async updateAdblockSettings(settings) {
        return this.request('/api/adblock/settings', {
            method: 'POST',
            body: JSON.stringify(settings)
        });
    }

    // Routing API
    async getRoutingRules() {
        return this.request('/api/routing/rules');
    }

    async addRoutingRule(rule) {
        return this.request('/api/routing/rules/add', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async deleteRoutingRule(ruleId) {
        return this.request('/api/routing/rules/delete', {
            method: 'POST',
            body: JSON.stringify({ id: ruleId })
        });
    }

    // Subscriptions API
    async getSubscriptions() {
        return this.request('/api/subscriptions');
    }

    async addSubscription(subscription) {
        return this.request('/api/subscriptions/add', {
            method: 'POST',
            body: JSON.stringify(subscription)
        });
    }

    async updateSubscription(id, subscription) {
        return this.request('/api/subscriptions/update', {
            method: 'POST',
            body: JSON.stringify({ id, ...subscription })
        });
    }

    async deleteSubscription(id) {
        return this.request('/api/subscriptions/delete', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
    }

    async enableSubscription(id, enabled) {
        return this.request('/api/subscriptions/enable', {
            method: 'POST',
            body: JSON.stringify({ id, enabled })
        });
    }

    async updateAllSubscriptions() {
        return this.request('/api/subscriptions/update-all', {
            method: 'POST'
        });
    }

    // Outbounds API
    async getOutbounds() {
        return this.request('/api/outbounds');
    }

    async addOutbound(outbound) {
        return this.request('/api/outbounds/add', {
            method: 'POST',
            body: JSON.stringify(outbound)
        });
    }

    async updateOutbound(tag, outbound) {
        return this.request('/api/outbounds/update', {
            method: 'POST',
            body: JSON.stringify({ tag, ...outbound })
        });
    }

    async deleteOutbound(tag) {
        return this.request('/api/outbounds/delete', {
            method: 'POST',
            body: JSON.stringify({ tag })
        });
    }

    // Outbound Groups API
    async getOutboundGroups() {
        return this.request('/api/outbound-groups');
    }

    async addOutboundGroup(group) {
        return this.request('/api/outbound-groups/add', {
            method: 'POST',
            body: JSON.stringify(group)
        });
    }

    async updateOutboundGroup(tag, group) {
        return this.request('/api/outbound-groups/update', {
            method: 'POST',
            body: JSON.stringify({ tag, ...group })
        });
    }

    async deleteOutboundGroup(tag) {
        return this.request('/api/outbound-groups/delete', {
            method: 'POST',
            body: JSON.stringify({ tag })
        });
    }

    // Geo databases API
    async getGeoStatus() {
        return this.request('/api/geo/status');
    }

    async updateGeoDatabases() {
        return this.request('/api/geo/update', {
            method: 'POST'
        });
    }

    async reloadGeoDatabases() {
        return this.request('/api/geo/reload', {
            method: 'POST'
        });
    }

    async getGeoSettings() {
        return this.request('/api/geo/settings');
    }

    async updateGeoSettings(settings) {
        return this.request('/api/geo/settings', {
            method: 'POST',
            body: JSON.stringify(settings)
        });
    }
}

// Создаем глобальный экземпляр API
const api = new WhisperaAPI();

