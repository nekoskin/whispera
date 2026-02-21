import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Outbound {
    tag: string;
    type: string;
    address: string;
    protocol: string;
    latency: number;
    availability: number;
    enabled: boolean;
}

@Injectable()
export class OutboundsService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getOutbounds(token: string): Promise<Outbound[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/outbounds`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.outbounds || response.data || [];
    }

    async addOutbound(token: string, outbound: Partial<Outbound>): Promise<Outbound> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/outbounds/add`,
                outbound,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteOutbound(token: string, tag: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/outbounds/delete`,
                { tag },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }
}
