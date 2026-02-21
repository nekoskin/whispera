import type { Response } from 'express';
import { StatsService } from './stats.service';
export declare class StatsController {
    private readonly statsService;
    constructor(statsService: StatsService);
    getTrafficStats(auth: string, period: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getUserTraffic(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getChartData(auth: string, period: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
