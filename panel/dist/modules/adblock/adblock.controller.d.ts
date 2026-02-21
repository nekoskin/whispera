import type { Response } from 'express';
import { AdblockService, AdblockRule } from './adblock.service';
export declare class AdblockController {
    private readonly adblockService;
    constructor(adblockService: AdblockService);
    getStats(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getRules(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addRule(auth: string, rule: Partial<AdblockRule>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteRule(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    updateSettings(auth: string, settings: any, res: Response): Promise<Response<any, Record<string, any>>>;
}
