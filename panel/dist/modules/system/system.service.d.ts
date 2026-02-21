import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface SystemInfo {
    version: string;
    uptime: number;
    go_version: string;
    server_ip: string;
    public_key: string;
}
export interface SystemStats {
    total_users: number;
    active_sessions: number;
    total_upload: number;
    total_download: number;
}
export declare class SystemService {
    private readonly httpService;
    private readonly configService;
    private readonly logger;
    private readonly backendUrl;
    private readonly requestTimeout;
    constructor(httpService: HttpService, configService: ConfigService);
    getSystemInfo(token: string): Promise<SystemInfo>;
    getStats(token: string): Promise<SystemStats>;
    reloadConfig(token: string): Promise<void>;
    getHealth(): Promise<any>;
}
