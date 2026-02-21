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
exports.DashboardService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let DashboardService = class DashboardService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getDashboardData(token) {
        const [statsRes, infoRes] = await Promise.all([
            (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/stats`, {
                headers: { Authorization: `Bearer ${token}` },
            })).catch(() => ({ data: {} })),
            (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/system/info`, {
                headers: { Authorization: `Bearer ${token}` },
            })).catch(() => ({ data: {} })),
        ]);
        return {
            stats: statsRes.data,
            systemInfo: infoRes.data,
            recentActivity: statsRes.data?.recentActivity || [],
        };
    }
};
exports.DashboardService = DashboardService;
exports.DashboardService = DashboardService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], DashboardService);
//# sourceMappingURL=dashboard.service.js.map