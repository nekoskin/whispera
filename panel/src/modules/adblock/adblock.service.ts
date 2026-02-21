import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

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

@Injectable()
export class AdblockService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getStats(token: string): Promise<AdblockStats> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/adblock/stats`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            );
            return response.data;
        } catch (e) {
            if (e.response?.status === 404) return { total_blocked: 0, dns_blocked: 0, https_blocked: 0, ml_blocked: 0 };
            throw e;
        }
    }

    async getRules(token: string): Promise<AdblockRule[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/adblock/rules`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            );
            return response.data.rules || [];
        } catch (e) {
            if (e.response?.status === 404) return [];
            throw e;
        }
    }

    async addRule(token: string, rule: Partial<AdblockRule>): Promise<AdblockRule> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/adblock/rules/add`,
                rule,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteRule(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/adblock/rules/delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async updateSettings(token: string, settings: any): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/adblock/settings`,
                settings,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }
}
