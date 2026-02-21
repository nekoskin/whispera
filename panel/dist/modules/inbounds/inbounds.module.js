"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InboundsModule = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const inbounds_controller_1 = require("./inbounds.controller");
const inbounds_service_1 = require("./inbounds.service");
let InboundsModule = class InboundsModule {
};
exports.InboundsModule = InboundsModule;
exports.InboundsModule = InboundsModule = __decorate([
    (0, common_1.Module)({
        imports: [axios_1.HttpModule],
        controllers: [inbounds_controller_1.InboundsController],
        providers: [inbounds_service_1.InboundsService],
        exports: [inbounds_service_1.InboundsService],
    })
], InboundsModule);
//# sourceMappingURL=inbounds.module.js.map