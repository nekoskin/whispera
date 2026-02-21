import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { join } from 'path';
import * as express from 'express';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );

  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  });


  const publicPath = join(__dirname, '..', 'public');
  app.use(express.static(publicPath));

  const httpAdapter = app.getHttpAdapter();
  httpAdapter.get('*', (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.url.startsWith('/api/')) {
      return next();
    }
    res.sendFile(join(publicPath, 'index.html'));
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`🚀 Whispera Panel running on http://localhost:${port}`);
}
bootstrap();
