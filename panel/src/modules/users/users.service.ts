import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface User {
    id: string;
    email: string;
    plan_name: string;
    bytes_in: number;
    bytes_out: number;
    connections_today: number;
    is_active: boolean;
    created_at: string;
}

@Injectable()
export class UsersService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getUsers(token: string, limit = 50, offset = 0): Promise<User[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/v2/users`, {
                headers: { Authorization: `Bearer ${token}` },
                params: { limit, offset },
            }),
        );
        return response.data.users || [];
    }

    async getUser(token: string, id: string): Promise<User> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/v2/users/${id}`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }

    async createUser(token: string, email: string, password: string, trafficLimit?: number, validUntil?: string): Promise<User> {
        const payload: any = { email, password };
        if (trafficLimit !== undefined) payload.traffic_limit = trafficLimit;
        if (validUntil !== undefined) payload.valid_until = validUntil;

        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/v2/users`,
                payload,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.user;
    }

    async updateUser(token: string, id: string, email: string, password?: string): Promise<any> {
        const payload: any = { email };
        if (password) payload.password = password;

        const response = await firstValueFrom(
            this.httpService.put(
                `${this.backendUrl}/api/v2/users/${id}`,
                payload,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteUser(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.delete(`${this.backendUrl}/api/v2/users/${id}`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
    }

    async getUserStats(token: string, id: string): Promise<any> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/v2/users/${id}/stats`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data;
    }
}
