import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class LogsService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getLogs(token: string, limit = 100): Promise<string[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/logs`, {
                    headers: { Authorization: `Bearer ${token}` },
                    params: { limit },
                }),
            );
            return response.data.logs || [];
        } catch (e) {
            if (e.response?.status === 404) return ['Logs endpoint not available in backend'];
            throw e;
        }
    }
}
