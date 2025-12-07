import { Controller, Post, Body } from '@nestjs/common';

import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { Throttle } from '@nestjs/throttler';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User created' })
  @ApiResponse({ status: 400, description: 'Email already exists' })
  signup(@Body() body: SignupDto) {
    return this.authService.signup(body);
  }

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 900000 } })
  @ApiOperation({ summary: 'Login with email & password' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    schema: {
      example: { access_token: 'eyJhbGciOiJIUzI1NiIs...' },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  login(@Body() body: LoginDto) {
    return this.authService.login(body);
  }
}
