import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export declare class AuthService {
    private readonly httpService;
    private readonly configService;
    private readonly logger;
    private readonly backendUrl;
    private readonly requestTimeout;
    constructor(httpService: HttpService, configService: ConfigService);
    login(username: string, password: string): Promise<any>;
    validateToken(token: string): Promise<boolean>;
    registerUser(email: string, password: string): Promise<any>;
}
