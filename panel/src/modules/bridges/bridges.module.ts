import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { BridgesController } from './bridges.controller';
import { BridgesService } from './bridges.service';

@Module({
    imports: [HttpModule],
    controllers: [BridgesController],
    providers: [BridgesService],
    exports: [BridgesService],
})
export class BridgesModule { }
