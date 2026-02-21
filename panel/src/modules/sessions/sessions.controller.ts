import { Controller, Get, Post, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { SessionsService } from './sessions.service';

@Controller()
export class SessionsController {
    constructor(private readonly sessionsService: SessionsService) { }

    @Get('api/sessions')
    async getSessions(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const sessions = await this.sessionsService.getSessions(token);
            return res.json({ success: true, sessions });
        } catch {
            return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: 'Failed to fetch sessions' });
        }
    }

    @Post('api/sessions/:id/kill')
    async killSession(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.sessionsService.killSession(token, id);
            return res.json({ success: true });
        } catch {
            return res.status(HttpStatus.BAD_REQUEST).json({ success: false, error: 'Failed to kill session' });
        }
    }
}
