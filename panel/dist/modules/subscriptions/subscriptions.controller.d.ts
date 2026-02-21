import type { Response } from 'express';
import { SubscriptionsService, Subscription } from './subscriptions.service';
export declare class SubscriptionsController {
    private readonly subscriptionsService;
    constructor(subscriptionsService: SubscriptionsService);
    getSubscriptions(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addSubscription(auth: string, subscription: Partial<Subscription>, res: Response): Promise<Response<any, Record<string, any>>>;
    updateSubscription(auth: string, body: {
        id: string;
    } & Partial<Subscription>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteSubscription(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    updateAll(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
