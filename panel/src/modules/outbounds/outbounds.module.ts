import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { OutboundsController } from './outbounds.controller';
import { OutboundsService } from './outbounds.service';

@Module({
    imports: [HttpModule],
    controllers: [OutboundsController],
    providers: [OutboundsService],
    exports: [OutboundsService],
})
export class OutboundsModule { }
