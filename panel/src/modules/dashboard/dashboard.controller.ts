import { Controller, Get, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { DashboardService } from './dashboard.service';

@Controller()
export class DashboardController {
    constructor(private readonly dashboardService: DashboardService) { }

    @Get('api/dashboard')
    async getDashboard(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.dashboardService.getDashboardData(token);
            return res.json({ success: true, ...data });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch dashboard data' });
        }
    }
}
