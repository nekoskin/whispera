import type { Response } from 'express';
import { OutboundsService, Outbound } from './outbounds.service';
export declare class OutboundsController {
    private readonly outboundsService;
    constructor(outboundsService: OutboundsService);
    getOutbounds(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addOutbound(auth: string, outbound: Partial<Outbound>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteOutbound(auth: string, tag: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
