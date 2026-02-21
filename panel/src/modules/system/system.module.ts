import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SystemController } from './system.controller';
import { SystemService } from './system.service';

@Module({
    imports: [HttpModule],
    controllers: [SystemController],
    providers: [SystemService],
    exports: [SystemService],
})
export class SystemModule { }
