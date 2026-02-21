import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface AdblockStats {
    total_blocked: number;
    dns_blocked: number;
    https_blocked: number;
    ml_blocked: number;
}
export interface AdblockRule {
    id: string;
    domain: string;
    type: string;
    enabled: boolean;
}
export declare class AdblockService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getStats(token: string): Promise<AdblockStats>;
    getRules(token: string): Promise<AdblockRule[]>;
    addRule(token: string, rule: Partial<AdblockRule>): Promise<AdblockRule>;
    deleteRule(token: string, id: string): Promise<void>;
    updateSettings(token: string, settings: any): Promise<void>;
}
