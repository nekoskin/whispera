import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface DashboardData {
    stats: {
        total_users: number;
        active_sessions: number;
        total_upload: number;
        total_download: number;
    };
    systemInfo: {
        version: string;
        uptime: number;
        server_ip: string;
    };
    recentActivity: any[];
}

@Injectable()
export class DashboardService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getDashboardData(token: string): Promise<DashboardData> {
        const [statsRes, infoRes] = await Promise.all([
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            ).catch(() => ({ data: {} })),
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/system/info`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            ).catch(() => ({ data: {} })),
        ]);

        return {
            stats: statsRes.data,
            systemInfo: infoRes.data,
            recentActivity: statsRes.data?.recentActivity || [],
        };
    }
}
