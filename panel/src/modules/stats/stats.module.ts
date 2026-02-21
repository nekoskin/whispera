import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';

@Module({
    imports: [HttpModule],
    controllers: [StatsController],
    providers: [StatsService],
    exports: [StatsService],
})
export class StatsModule { }
