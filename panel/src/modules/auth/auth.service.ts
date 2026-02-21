import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly backendUrl: string;
    private readonly requestTimeout = 10000;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async login(username: string, password: string): Promise<any> {
        try {
            const response = await firstValueFrom(
                this.httpService.post(`${this.backendUrl}/api/login`, {
                    username,
                    password,
                }, {
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.warn(`Login failed: ${err.message}`);
            if (err.response?.status === 401 || err.response?.status === 429) {
                throw err;
            }
            throw new Error('Authentication service unavailable');
        }
    }

    async validateToken(token: string): Promise<boolean> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/v1/health`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError(() => of({ status: 0 })),
                ),
            );
            return response.status === 200;
        } catch {
            return false;
        }
    }

    async registerUser(email: string, password: string): Promise<any> {
        try {
            const response = await firstValueFrom(
                this.httpService.post(`${this.backendUrl}/api/v2/auth/register`, {
                    email,
                    password,
                }, {
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                ),
            );
            return response.data;
        } catch (err) {
            this.logger.warn(`Registration failed: ${err.message}`);
            throw err;
        }
    }
}
