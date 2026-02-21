import type { Response } from 'express';
import { LogsService } from './logs.service';
export declare class LogsController {
    private readonly logsService;
    constructor(logsService: LogsService);
    getLogs(auth: string, limit: number, res: Response): Promise<Response<any, Record<string, any>>>;
}
