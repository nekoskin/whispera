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
exports.LogsService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let LogsService = class LogsService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getLogs(token, limit = 100) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/logs`, {
                headers: { Authorization: `Bearer ${token}` },
                params: { limit },
            }));
            return response.data.logs || [];
        }
        catch (e) {
            if (e.response?.status === 404)
                return ['Logs endpoint not available in backend'];
            throw e;
        }
    }
};
exports.LogsService = LogsService;
exports.LogsService = LogsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], LogsService);
//# sourceMappingURL=logs.service.js.map