import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

export interface Session {
    id: string;
    user_id: string;
    client_ip: string;
    connected_at: string;
    bytes_in: number;
    bytes_out: number;
}

@Injectable()
export class SessionsService {
    private readonly logger = new Logger(SessionsService.name);
    private readonly backendUrl: string;
    private readonly requestTimeout = 10000;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getSessions(token: string): Promise<Session[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/sessions`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to get sessions: ${err.message}`);
                        return of({ data: { sessions: [] } });
                    }),
                ),
            );
            return response.data.sessions || response.data || [];
        } catch (err) {
            this.logger.error(`Sessions error: ${err.message}`);
            return [];
        }
    }

    async killSession(token: string, id: string): Promise<void> {
        try {
            await firstValueFrom(
                this.httpService.post(
                    `${this.backendUrl}/api/sessions/${id}/kill`,
                    {},
                    {
                        headers: { Authorization: `Bearer ${token}` },
                        timeout: this.requestTimeout,
                    },
                ).pipe(
                    timeout(this.requestTimeout),
                    catchError(err => {
                        this.logger.warn(`Failed to kill session ${id}: ${err.message}`);
                        throw err;
                    }),
                ),
            );
        } catch (err) {
            this.logger.error(`Kill session error: ${err.message}`);
            throw err;
        }
    }
}
