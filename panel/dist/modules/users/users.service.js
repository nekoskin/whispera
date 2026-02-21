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
Object.defineProperty(exports, "__esModule", { value: true });
exports.UsersService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let UsersService = class UsersService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getUsers(token, limit = 50, offset = 0) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v2/users`, {
            headers: { Authorization: `Bearer ${token}` },
            params: { limit, offset },
        }));
        return response.data.users || [];
    }
    async getUser(token, id) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v2/users/${id}`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
    async createUser(token, email, password, trafficLimit, validUntil) {
        const payload = { email, password };
        if (trafficLimit !== undefined)
            payload.traffic_limit = trafficLimit;
        if (validUntil !== undefined)
            payload.valid_until = validUntil;
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/v2/users`, payload, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data.user;
    }
    async updateUser(token, id, email, password) {
        const payload = { email };
        if (password)
            payload.password = password;
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.put(`${this.backendUrl}/api/v2/users/${id}`, payload, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data;
    }
    async deleteUser(token, id) {
        await (0, rxjs_1.firstValueFrom)(this.httpService.delete(`${this.backendUrl}/api/v2/users/${id}`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
    }
    async getUserStats(token, id) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v2/users/${id}/stats`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data;
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], UsersService);
//# sourceMappingURL=users.service.js.map