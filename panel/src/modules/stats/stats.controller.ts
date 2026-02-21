import { Controller, Get, Query, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { StatsService } from './stats.service';

@Controller()
export class StatsController {
    constructor(private readonly statsService: StatsService) { }

    @Get('api/stats/traffic')
    async getTrafficStats(
        @Headers('authorization') auth: string,
        @Query('period') period: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.statsService.getTrafficStats(token, period || '24h');
            return res.json({ success: true, ...stats });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch traffic stats' });
        }
    }

    @Get('api/stats/users')
    async getUserTraffic(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const users = await this.statsService.getUserTraffic(token);
            return res.json({ success: true, users });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch user traffic' });
        }
    }

    @Get('api/stats/chart')
    async getChartData(
        @Headers('authorization') auth: string,
        @Query('period') period: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.statsService.getChartData(token, period || '24h');
            return res.json({ success: true, ...data });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch chart data' });
        }
    }
}
