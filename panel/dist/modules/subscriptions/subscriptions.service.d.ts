import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Subscription {
    id: string;
    name: string;
    url: string;
    interval: string;
    lastUpdate: string;
    serverCount: number;
    enabled: boolean;
}
export declare class SubscriptionsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getSubscriptions(token: string): Promise<Subscription[]>;
    addSubscription(token: string, subscription: Partial<Subscription>): Promise<Subscription>;
    updateSubscription(token: string, id: string, subscription: Partial<Subscription>): Promise<Subscription>;
    deleteSubscription(token: string, id: string): Promise<void>;
    updateAll(token: string): Promise<void>;
}
