import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface User {
    id: string;
    email: string;
    plan_name: string;
    bytes_in: number;
    bytes_out: number;
    connections_today: number;
    is_active: boolean;
    created_at: string;
}
export declare class UsersService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getUsers(token: string, limit?: number, offset?: number): Promise<User[]>;
    getUser(token: string, id: string): Promise<User>;
    createUser(token: string, email: string, password: string, trafficLimit?: number, validUntil?: string): Promise<User>;
    updateUser(token: string, id: string, email: string, password?: string): Promise<any>;
    deleteUser(token: string, id: string): Promise<void>;
    getUserStats(token: string, id: string): Promise<any>;
}
