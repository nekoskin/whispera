import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Outbound {
    tag: string;
    type: string;
    address: string;
    protocol: string;
    latency: number;
    availability: number;
    enabled: boolean;
}
export declare class OutboundsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getOutbounds(token: string): Promise<Outbound[]>;
    addOutbound(token: string, outbound: Partial<Outbound>): Promise<Outbound>;
    deleteOutbound(token: string, tag: string): Promise<void>;
}
