import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export declare class LogsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getLogs(token: string, limit?: number): Promise<string[]>;
}
