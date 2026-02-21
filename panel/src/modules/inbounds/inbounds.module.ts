import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { InboundsController } from './inbounds.controller';
import { InboundsService } from './inbounds.service';

@Module({
    imports: [HttpModule],
    controllers: [InboundsController],
    providers: [InboundsService],
    exports: [InboundsService],
})
export class InboundsModule { }
