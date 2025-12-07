import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';

@Injectable()
export class AuthService {
  private readonly bcryptRounds = 12;
  private readonly accessTokenExpiry = '24h';
  private readonly refreshTokenExpiry = '7d';

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(body: SignupDto) {
    this.validatePasswordStrength(body.password);

    const exists = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    if (exists) {
      throw new ConflictException('Email already exists');
    }

    const hash = await bcrypt.hash(body.password, this.bcryptRounds);

    const user = await this.prisma.user.create({
      data: {
        email: body.email,
        password: hash,
        name: body.name,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    return {
      message: 'User created successfully',
      user,
    };
  }

  async login(body: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    const passwordHash = user?.password || '';
    const isValidPassword = await bcrypt.compare(body.password, passwordHash);

    if (!user || !isValidPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.generateTokens(user.id, user.email);

    await this.updateRefreshToken(user.id, tokens.refresh_token);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return tokens;
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    return { message: 'Logged out successfully' };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('Access denied');
    }

    const isValid = await bcrypt.compare(refreshToken, user.refreshToken);

    if (!isValid) {
      throw new UnauthorizedException('Access denied');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  private async generateTokens(userId: string, email: string) {
    const payload = { sub: userId, email };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('auth.jwtSecret'),
        expiresIn: this.accessTokenExpiry,
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('auth.jwtRefreshSecret'),
        expiresIn: this.refreshTokenExpiry,
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenExpiry,
    };
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const hash = await bcrypt.hash(refreshToken, this.bcryptRounds);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hash },
    });
  }

  private validatePasswordStrength(password: string) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(
        `Password must be at least ${minLength} characters long`,
      );
    }

    if (!hasUpperCase || !hasLowerCase) {
      throw new BadRequestException(
        'Password must contain both uppercase and lowercase letters',
      );
    }

    if (!hasNumber) {
      throw new BadRequestException(
        'Password must contain at least one number',
      );
    }

    if (!hasSpecialChar) {
      throw new BadRequestException(
        'Password must contain at least one special character',
      );
    }

    const commonPasswords = ['password', '12345678', 'qwerty'];
    if (commonPasswords.includes(password.toLowerCase())) {
      throw new BadRequestException('Password is too common');
    }
  }
}
