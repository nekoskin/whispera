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
exports.SubscriptionsController = void 0;
const common_1 = require("@nestjs/common");
const subscriptions_service_1 = require("./subscriptions.service");
let SubscriptionsController = class SubscriptionsController {
    subscriptionsService;
    constructor(subscriptionsService) {
        this.subscriptionsService = subscriptionsService;
    }
    async getSubscriptions(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const subscriptions = await this.subscriptionsService.getSubscriptions(token);
            return res.json({ success: true, subscriptions });
        }
        catch {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch subscriptions' });
        }
    }
    async addSubscription(auth, subscription, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.subscriptionsService.addSubscription(token, subscription);
            return res.json({ success: true, subscription: result });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to add subscription' });
        }
    }
    async updateSubscription(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const { id, ...subscription } = body;
            const result = await this.subscriptionsService.updateSubscription(token, id, subscription);
            return res.json({ success: true, subscription: result });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to update subscription' });
        }
    }
    async deleteSubscription(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.subscriptionsService.deleteSubscription(token, id);
            return res.json({ success: true });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete subscription' });
        }
    }
    async updateAll(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.subscriptionsService.updateAll(token);
            return res.json({ success: true });
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to update all subscriptions' });
        }
    }
};
exports.SubscriptionsController = SubscriptionsController;
__decorate([
    (0, common_1.Get)('api/subscriptions'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "getSubscriptions", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/add'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "addSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/update'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "updateSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "deleteSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/update-all'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "updateAll", null);
exports.SubscriptionsController = SubscriptionsController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [subscriptions_service_1.SubscriptionsService])
], SubscriptionsController);
//# sourceMappingURL=subscriptions.controller.js.map