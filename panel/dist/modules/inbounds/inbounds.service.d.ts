import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Inbound {
    tag: string;
    protocol: string;
    listen: string;
    port: number;
    transport: string;
    security: string;
    private_key?: string;
    public_key?: string;
}
export declare class InboundsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getInbounds(token: string): Promise<Inbound[]>;
    addInbound(token: string, inbound: Partial<Inbound>): Promise<Inbound>;
    deleteInbound(token: string, tag: string): Promise<void>;
    getPublicKey(token: string, port: number): Promise<string>;
}
