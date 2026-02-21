import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { AdblockController } from './adblock.controller';
import { AdblockService } from './adblock.service';

@Module({
    imports: [HttpModule],
    controllers: [AdblockController],
    providers: [AdblockService],
    exports: [AdblockService],
})
export class AdblockModule { }
