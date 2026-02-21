import { Controller, Get, Post, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { AdblockService, AdblockRule } from './adblock.service';

@Controller()
export class AdblockController {
    constructor(private readonly adblockService: AdblockService) { }

    @Get('api/adblock/stats')
    async getStats(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.adblockService.getStats(token);
            return res.json(stats);
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch adblock stats' });
        }
    }

    @Get('api/adblock/rules')
    async getRules(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const rules = await this.adblockService.getRules(token);
            return res.json({ success: true, rules });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch adblock rules' });
        }
    }

    @Post('api/adblock/rules/add')
    async addRule(
        @Headers('authorization') auth: string,
        @Body() rule: Partial<AdblockRule>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.adblockService.addRule(token, rule);
            return res.json({ success: true, rule: result });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to add rule' });
        }
    }

    @Post('api/adblock/rules/delete')
    async deleteRule(
        @Headers('authorization') auth: string,
        @Body('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.adblockService.deleteRule(token, id);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete rule' });
        }
    }

    @Post('api/adblock/settings')
    async updateSettings(
        @Headers('authorization') auth: string,
        @Body() settings: any,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.adblockService.updateSettings(token, settings);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to update settings' });
        }
    }
}
