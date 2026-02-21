import type { Response } from 'express';
import { DashboardService } from './dashboard.service';
export declare class DashboardController {
    private readonly dashboardService;
    constructor(dashboardService: DashboardService);
    getDashboard(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
