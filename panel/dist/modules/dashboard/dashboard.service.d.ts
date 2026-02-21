import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface DashboardData {
    stats: {
        total_users: number;
        active_sessions: number;
        total_upload: number;
        total_download: number;
    };
    systemInfo: {
        version: string;
        uptime: number;
        server_ip: string;
    };
    recentActivity: any[];
}
export declare class DashboardService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getDashboardData(token: string): Promise<DashboardData>;
}
