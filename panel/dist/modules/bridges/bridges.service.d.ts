import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Bridge {
    id: string;
    url: string;
    status: string;
    last_seen: string;
}
export declare class BridgesService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getBridges(token: string): Promise<Bridge[]>;
    addBridge(token: string, bridge: Partial<Bridge>): Promise<Bridge>;
    deleteBridge(token: string, id: string): Promise<void>;
    getCloudInit(token: string): Promise<string>;
}
