import type { Response } from 'express';
import { SessionsService } from './sessions.service';
export declare class SessionsController {
    private readonly sessionsService;
    constructor(sessionsService: SessionsService);
    getSessions(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    killSession(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
