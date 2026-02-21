import type { Response } from 'express';
import { InboundsService, Inbound } from './inbounds.service';
export declare class InboundsController {
    private readonly inboundsService;
    constructor(inboundsService: InboundsService);
    getInbounds(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addInbound(auth: string, inbound: Partial<Inbound>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteInbound(auth: string, tag: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getPublicKey(auth: string, port: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
