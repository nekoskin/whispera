import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { LogsController } from './logs.controller';
import { LogsService } from './logs.service';

@Module({
    imports: [HttpModule],
    controllers: [LogsController],
    providers: [LogsService],
    exports: [LogsService],
})
export class LogsModule { }
