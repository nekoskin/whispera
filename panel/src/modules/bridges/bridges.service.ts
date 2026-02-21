import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Bridge {
    id: string;
    url: string;
    status: string;
    last_seen: string;
}

@Injectable()
export class BridgesService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getBridges(token: string): Promise<Bridge[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-admin`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.bridges || response.data || [];
    }

    async addBridge(token: string, bridge: Partial<Bridge>): Promise<Bridge> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/bridge-add`,
                bridge,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteBridge(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/bridge-delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async getCloudInit(token: string): Promise<string> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/bridge-cloudinit`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }
}
