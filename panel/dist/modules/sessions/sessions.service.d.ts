import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Session {
    id: string;
    user_id: string;
    client_ip: string;
    connected_at: string;
    bytes_in: number;
    bytes_out: number;
}
export declare class SessionsService {
    private readonly httpService;
    private readonly configService;
    private readonly logger;
    private readonly backendUrl;
    private readonly requestTimeout;
    constructor(httpService: HttpService, configService: ConfigService);
    getSessions(token: string): Promise<Session[]>;
    killSession(token: string, id: string): Promise<void>;
}
