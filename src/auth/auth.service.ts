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

/**
 * Service responsible for handling user authentication operations
 * including signup, login, logout, token refresh, and user management.
 */
@Injectable()
export class AuthService {
  // Number of rounds for bcrypt password hashing (higher = more secure but slower)
  private readonly bcryptRounds = 12;
  // Expiry time for access tokens (24 hours)
  private readonly accessTokenExpiry = '24h';
  // Expiry time for refresh tokens (7 days)
  private readonly refreshTokenExpiry = '7d';

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  /**
   * Registers a new user in the system
   * @param body - User signup data including email, password, and optional name
   * @returns User creation confirmation with user data (excluding password)
   * @throws ConflictException if email already exists
   * @throws BadRequestException if password doesn't meet security requirements
   */
  async signup(body: SignupDto) {
    // Validate password strength before proceeding
    this.validatePasswordStrength(body.password);

    // Check if a user with this email already exists
    const exists = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    if (exists) {
      throw new ConflictException('Email already exists');
    }

    // Hash password with bcrypt using configured rounds for security
    const hash = await bcrypt.hash(body.password, this.bcryptRounds);

    // Create new user in database, explicitly excluding password from response
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

  /**
   * Authenticates a user with email and password
   * @param body - Login credentials including email and password
   * @returns JWT access and refresh tokens
   * @throws UnauthorizedException if credentials are invalid
   */
  async login(body: LoginDto) {
    // Fetch user by email from database
    const user = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    // Always run bcrypt.compare to prevent timing attacks
    // This ensures the response time is the same whether user exists or not
    const passwordHash = user?.password || '';
    const isValidPassword = await bcrypt.compare(body.password, passwordHash);

    if (!user || !isValidPassword) {
      // Generic error message to prevent user enumeration attacks
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is active/verified (if you have these fields)
    // if (!user.isActive) {
    //   throw new UnauthorizedException('Account is disabled');
    // }

    // Generate JWT access and refresh tokens for the authenticated user
    const tokens = await this.generateTokens(user.id, user.email);

    // Optional: Store refresh token hash in database for revocation
    // await this.updateRefreshToken(user.id, tokens.refresh_token);

    // Update last login timestamp for security monitoring
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return tokens;
  }

  /**
   * Logs out a user by invalidating their refresh token
   * @param userId - ID of the user to logout
   * @returns Confirmation message
   */
  async logout(userId: string) {
    // Invalidate refresh token in database by setting it to null
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    return { message: 'Logged out successfully' };
  }

  /**
   * Refreshes JWT tokens using a valid refresh token
   * @param userId - ID of the user requesting token refresh
   * @param refreshToken - The refresh token to validate
   * @returns New access and refresh tokens
   * @throws UnauthorizedException if refresh token is invalid
   */
  async refreshTokens(userId: string, refreshToken: string) {
    // Find user by ID
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    // Check if user exists and has a refresh token
    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('Access denied');
    }

    // Verify the provided refresh token matches the stored hash
    const isValid = await bcrypt.compare(refreshToken, user.refreshToken);

    if (!isValid) {
      throw new UnauthorizedException('Access denied');
    }

    // Generate new token pair
    const tokens = await this.generateTokens(user.id, user.email);
    // Update the stored refresh token with the new one (token rotation)
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  /**
   * Retrieves user information by ID
   * @param id - User ID to search for
   * @returns User data without sensitive information
   * @throws UnauthorizedException if user is not found
   */
  async findById(id: string) {
    // Find user by ID, selecting only non-sensitive fields
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

  // Private helper methods

  /**
   * Generates JWT access and refresh tokens for a user
   * @param userId - User ID to include in token payload
   * @param email - User email to include in token payload
   * @returns Object containing access token, refresh token, and metadata
   */
  private async generateTokens(userId: string, email: string) {
    // Create JWT payload with user information
    const payload = { sub: userId, email };

    // Generate both tokens in parallel for better performance
    const [accessToken, refreshToken] = await Promise.all([
      // Access token with shorter expiry for security
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('auth.jwtSecret'),
        expiresIn: this.accessTokenExpiry,
      }),
      // Refresh token with longer expiry for convenience
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('auth.jwtRefreshSecret'),
        expiresIn: this.refreshTokenExpiry,
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes in seconds (note: should match actual token expiry)
    };
  }

  /**
   * Stores a hashed refresh token in the database
   * @param userId - User ID to update
   * @param refreshToken - Refresh token to hash and store
   */
  private async updateRefreshToken(userId: string, refreshToken: string) {
    // Hash refresh token before storing for security
    const hash = await bcrypt.hash(refreshToken, this.bcryptRounds);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hash },
    });
  }

  /**
   * Validates password strength against security requirements
   * @param password - Password to validate
   * @throws BadRequestException if password doesn't meet requirements
   */
  private validatePasswordStrength(password: string) {
    // Define minimum password requirements
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    // Check minimum length
    if (password.length < minLength) {
      throw new BadRequestException(
        `Password must be at least ${minLength} characters long`,
      );
    }

    // Check for both uppercase and lowercase letters
    if (!hasUpperCase || !hasLowerCase) {
      throw new BadRequestException(
        'Password must contain both uppercase and lowercase letters',
      );
    }

    // Check for at least one number
    if (!hasNumber) {
      throw new BadRequestException(
        'Password must contain at least one number',
      );
    }

    // Check for at least one special character
    if (!hasSpecialChar) {
      throw new BadRequestException(
        'Password must contain at least one special character',
      );
    }

    // Check against common passwords (in production, use a library like zxcvbn)
    const commonPasswords = ['password', '12345678', 'qwerty'];
    if (commonPasswords.includes(password.toLowerCase())) {
      throw new BadRequestException('Password is too common');
    }
  }
}
