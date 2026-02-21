import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Subscription {
    id: string;
    name: string;
    url: string;
    interval: string;
    lastUpdate: string;
    serverCount: number;
    enabled: boolean;
}

@Injectable()
export class SubscriptionsService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getSubscriptions(token: string): Promise<Subscription[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/subscriptions`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            );
            return response.data.subscriptions || response.data || [];
        } catch (e) {
            // Graceful fallback if endpoint doesn't exist yet
            if (e.response?.status === 404) return [];
            throw e;
        }
    }

    async addSubscription(token: string, subscription: Partial<Subscription>): Promise<Subscription> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/add`,
                subscription,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async updateSubscription(token: string, id: string, subscription: Partial<Subscription>): Promise<Subscription> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/update`,
                { id, ...subscription },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteSubscription(token: string, id: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/delete`,
                { id },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async updateAll(token: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/subscriptions/update-all`,
                {},
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }
}
