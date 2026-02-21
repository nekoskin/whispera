import type { Response } from 'express';
import { UsersService } from './users.service';
declare class CreateUserDto {
    email: string;
    password: string;
    traffic_limit?: number;
    valid_until?: string;
}
export declare class UsersController {
    private readonly usersService;
    constructor(usersService: UsersService);
    getUsers(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    createUser(auth: string, dto: CreateUserDto, res: Response): Promise<Response<any, Record<string, any>>>;
    updateUser(auth: string, id: string, body: {
        email: string;
        password?: string;
    }, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteUser(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getUserStats(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
export {};
