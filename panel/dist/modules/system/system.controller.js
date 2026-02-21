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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SystemController = void 0;
const common_1 = require("@nestjs/common");
const system_service_1 = require("./system.service");
let SystemController = class SystemController {
    systemService;
    constructor(systemService) {
        this.systemService = systemService;
    }
    async getSystemInfo(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const info = await this.systemService.getSystemInfo(token);
            return res.json(info);
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch system info' });
        }
    }
    async getStats(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.systemService.getStats(token);
            return res.json(stats);
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch stats' });
        }
    }
    async reloadConfig(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.systemService.reloadConfig(token);
            return res.json({ success: true, message: 'Config reloaded' });
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to reload config' });
        }
    }
    async getHealth(res) {
        try {
            const health = await this.systemService.getHealth();
            return res.json(health);
        }
        catch {
            return res.status(common_1.HttpStatus.SERVICE_UNAVAILABLE).json({ status: 'unavailable' });
        }
    }
};
exports.SystemController = SystemController;
__decorate([
    (0, common_1.Get)('api/system/info'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getSystemInfo", null);
__decorate([
    (0, common_1.Get)('api/stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getStats", null);
__decorate([
    (0, common_1.Post)('api/system/reload'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "reloadConfig", null);
__decorate([
    (0, common_1.Get)('api/health'),
    __param(0, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getHealth", null);
exports.SystemController = SystemController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [system_service_1.SystemService])
], SystemController);
//# sourceMappingURL=system.controller.js.map