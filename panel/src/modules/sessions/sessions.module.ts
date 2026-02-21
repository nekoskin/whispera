import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SessionsController } from './sessions.controller';
import { SessionsService } from './sessions.service';

@Module({
    imports: [HttpModule],
    controllers: [SessionsController],
    providers: [SessionsService],
    exports: [SessionsService],
})
export class SessionsModule { }
