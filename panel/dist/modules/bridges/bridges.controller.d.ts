import type { Response } from 'express';
import { BridgesService, Bridge } from './bridges.service';
export declare class BridgesController {
    private readonly bridgesService;
    constructor(bridgesService: BridgesService);
    getBridges(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addBridge(auth: string, bridge: Partial<Bridge>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteBridge(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getCloudInit(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
