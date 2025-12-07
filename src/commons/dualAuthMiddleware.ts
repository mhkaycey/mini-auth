import {
  Injectable,
  Logger,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { KeysService } from '../keys/keys.service';
import { JwtService } from '@nestjs/jwt';

interface AuthenticatedRequest extends Request {
  user?: Record<string, unknown>;
  authType?: 'jwt' | 'api-key';
  apiKey?: Record<string, unknown>;
}

@Injectable()
export class DualAuthMiddleware implements NestMiddleware {
  private readonly logger = new Logger(DualAuthMiddleware.name);
  constructor(
    private keysService: KeysService,
    private jwtService: JwtService,
  ) {}

  async use(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    const authHeader: string | undefined = req.headers.authorization;
    const apiKey: string | undefined = req.headers['x-api-key'] as
      | string
      | undefined;

    if (apiKey) {
      try {
        const result = await this.keysService.validate(apiKey);
        if (result) {
          req.user = result.user;
          req.authType = 'api-key';
          req.apiKey = result.apiKey;
          return next();
        }
      } catch {
        this.logger.error('Failed to validate API key');
        // next();
      }
    }

    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.split(' ')[1];
        if (!token) {
          throw new UnauthorizedException('Token not provided');
        }

        const payload: Record<string, unknown> = this.jwtService.verify(token, {
          secret: process.env.JWT_SECRET!,
        });
        req.user = payload;
        req.authType = 'jwt';
        return next();
      } catch {
        this.logger.error('Failed to validate JWT token');
        // next();
      }
    }

    next();
  }
}
