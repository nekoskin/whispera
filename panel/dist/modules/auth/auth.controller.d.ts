import type { Response } from 'express';
import { AuthService } from './auth.service';
declare class LoginDto {
    username: string;
    password: string;
}
declare class RegisterDto {
    email: string;
    password: string;
}
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    loginPage(res: Response): void;
    login(dto: LoginDto, res: Response): Promise<Response<any, Record<string, any>>>;
    register(dto: RegisterDto, res: Response): Promise<Response<any, Record<string, any>>>;
    logout(res: Response): Response<any, Record<string, any>>;
}
export {};
