import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { AuthConfig } from 'src/config/authConfig';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService): Promise<any> => {
        const auth = configService.get<AuthConfig>('auth');
        const secret = auth?.jwt.secret;
        if (!secret) {
          throw new Error('JWT_SECRET environment variable must be set');
        }
        return {
          secret,
          signOptions: {
            expiresIn: (auth?.jwt.expiresIn || '24h') as any,
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [JwtModule],
})
export class AuthModule {}
