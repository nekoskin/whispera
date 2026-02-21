import type { Response } from 'express';
import { SystemService } from './system.service';
export declare class SystemController {
    private readonly systemService;
    constructor(systemService: SystemService);
    getSystemInfo(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getStats(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    reloadConfig(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getHealth(res: Response): Promise<Response<any, Record<string, any>>>;
}
