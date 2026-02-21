import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SubscriptionsController } from './subscriptions.controller';
import { SubscriptionsService } from './subscriptions.service';

@Module({
    imports: [HttpModule],
    controllers: [SubscriptionsController],
    providers: [SubscriptionsService],
    exports: [SubscriptionsService],
})
export class SubscriptionsModule { }
