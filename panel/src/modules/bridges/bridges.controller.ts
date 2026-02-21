import { Controller, Get, Post, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { BridgesService, Bridge } from './bridges.service';

@Controller()
export class BridgesController {
    constructor(private readonly bridgesService: BridgesService) { }

    @Get('api/bridges')
    async getBridges(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const bridges = await this.bridgesService.getBridges(token);
            return res.json({ success: true, bridges });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch bridges' });
        }
    }

    @Post('api/bridges')
    async addBridge(
        @Headers('authorization') auth: string,
        @Body() bridge: Partial<Bridge>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.bridgesService.addBridge(token, bridge);
            return res.json({ success: true, bridge: result });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to add bridge' });
        }
    }

    @Post('api/bridges/delete')
    async deleteBridge(
        @Headers('authorization') auth: string,
        @Body('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.bridgesService.deleteBridge(token, id);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to delete bridge' });
        }
    }

    @Get('api/bridges/cloudinit')
    async getCloudInit(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const script = await this.bridgesService.getCloudInit(token);
            return res.send(script);
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send('Failed to generate cloud-init');
        }
    }
}
