"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var AuthService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
const rxjs_2 = require("rxjs");
let AuthService = AuthService_1 = class AuthService {
    httpService;
    configService;
    logger = new common_1.Logger(AuthService_1.name);
    backendUrl;
    requestTimeout = 10000;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async login(username, password) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/login`, {
                username,
                password,
            }, {
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout)));
            return response.data;
        }
        catch (err) {
            this.logger.warn(`Login failed: ${err.message}`);
            if (err.response?.status === 401 || err.response?.status === 429) {
                throw err;
            }
            throw new Error('Authentication service unavailable');
        }
    }
    async validateToken(token) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v1/health`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(() => (0, rxjs_2.of)({ status: 0 }))));
            return response.status === 200;
        }
        catch {
            return false;
        }
    }
    async registerUser(email, password) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/v2/auth/register`, {
                email,
                password,
            }, {
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout)));
            return response.data;
        }
        catch (err) {
            this.logger.warn(`Registration failed: ${err.message}`);
            throw err;
        }
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = AuthService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], AuthService);
//# sourceMappingURL=auth.service.js.map