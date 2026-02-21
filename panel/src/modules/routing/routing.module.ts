import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { RoutingController } from './routing.controller';
import { RoutingService } from './routing.service';

@Module({
    imports: [HttpModule],
    controllers: [RoutingController],
    providers: [RoutingService],
    exports: [RoutingService],
})
export class RoutingModule { }
