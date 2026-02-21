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
var StatsService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatsService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
const rxjs_2 = require("rxjs");
let StatsService = StatsService_1 = class StatsService {
    httpService;
    configService;
    logger = new common_1.Logger(StatsService_1.name);
    backendUrl;
    requestTimeout = 10000;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getTrafficStats(token, period = '24h') {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/stats/traffic`, {
                headers: { Authorization: `Bearer ${token}` },
                params: { period },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to get traffic stats: ${err.message}`);
                return (0, rxjs_2.of)({ data: { total_upload: 0, total_download: 0, total_traffic: 0, active_users: 0, user_stats: [] } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`Traffic stats error: ${err.message}`);
            return { total_upload: 0, total_download: 0, total_traffic: 0, active_users: 0, user_stats: [] };
        }
    }
    async getUserTraffic(token) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/stats/users`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to get user traffic: ${err.message}`);
                return (0, rxjs_2.of)({ data: { users: [] } });
            })));
            return response.data.users || [];
        }
        catch (err) {
            this.logger.error(`User traffic error: ${err.message}`);
            return [];
        }
    }
    async getChartData(token, period = '24h') {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/stats/chart`, {
                headers: { Authorization: `Bearer ${token}` },
                params: { period },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to get chart data: ${err.message}`);
                return (0, rxjs_2.of)({ data: { labels: [], upload: [], download: [] } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`Chart data error: ${err.message}`);
            return { labels: [], upload: [], download: [] };
        }
    }
};
exports.StatsService = StatsService;
exports.StatsService = StatsService = StatsService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], StatsService);
//# sourceMappingURL=stats.service.js.map