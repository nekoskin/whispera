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
exports.BridgesController = void 0;
const common_1 = require("@nestjs/common");
const bridges_service_1 = require("./bridges.service");
let BridgesController = class BridgesController {
    bridgesService;
    constructor(bridgesService) {
        this.bridgesService = bridgesService;
    }
    async getBridges(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const bridges = await this.bridgesService.getBridges(token);
            return res.json({ success: true, bridges });
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch bridges' });
        }
    }
    async addBridge(auth, bridge, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.bridgesService.addBridge(token, bridge);
            return res.json({ success: true, bridge: result });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to add bridge' });
        }
    }
    async deleteBridge(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.bridgesService.deleteBridge(token, id);
            return res.json({ success: true });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete bridge' });
        }
    }
    async getCloudInit(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).send('Failed to generate cloud-init');
        }
    }
};
exports.BridgesController = BridgesController;
__decorate([
    (0, common_1.Get)('api/bridges'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getBridges", null);
__decorate([
    (0, common_1.Post)('api/bridges'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "addBridge", null);
__decorate([
    (0, common_1.Post)('api/bridges/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "deleteBridge", null);
__decorate([
    (0, common_1.Get)('api/bridges/cloudinit'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], BridgesController.prototype, "getCloudInit", null);
exports.BridgesController = BridgesController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [bridges_service_1.BridgesService])
], BridgesController);
//# sourceMappingURL=bridges.controller.js.map