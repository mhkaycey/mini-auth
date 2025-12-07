import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { DualAuthMiddleware } from './commons/dualAuthMiddleware';
import { ConfigModule } from '@nestjs/config';
import authConfig from './config/authConfig';
import { AuthModule } from './auth/auth.module';
import { KeysModule } from './keys/keys.module';
import { PrismaModule } from 'prisma/prisma.module';
import appConfig from './config/appConfig';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ExampleModule } from './example/example.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [authConfig, appConfig],
    }),
    PrismaModule,
    AuthModule,
    KeysModule,
    ExampleModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(DualAuthMiddleware).forRoutes('*');
  }
}
