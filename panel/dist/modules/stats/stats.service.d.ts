import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface TrafficStats {
    total_upload: number;
    total_download: number;
    total_traffic: number;
    active_users: number;
    user_stats: UserTrafficStats[];
    chart_data?: ChartData;
}
export interface UserTrafficStats {
    user_id: string;
    name: string;
    upload: number;
    download: number;
    total: number;
    limit: number;
    used_percent: number;
}
export interface ChartData {
    labels: string[];
    upload: number[];
    download: number[];
}
export declare class StatsService {
    private readonly httpService;
    private readonly configService;
    private readonly logger;
    private readonly backendUrl;
    private readonly requestTimeout;
    constructor(httpService: HttpService, configService: ConfigService);
    getTrafficStats(token: string, period?: string): Promise<TrafficStats>;
    getUserTraffic(token: string): Promise<UserTrafficStats[]>;
    getChartData(token: string, period?: string): Promise<ChartData>;
}
