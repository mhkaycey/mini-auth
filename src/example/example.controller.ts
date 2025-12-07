import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiHeader,
} from '@nestjs/swagger';

@ApiTags('Example')
@Controller('example')
export class ExampleController {
  @Get('public')
  @ApiOperation({ summary: 'Public endpoint – no auth' })
  @ApiResponse({ status: 200, description: 'Returns a public message' })
  public() {
    return { message: 'Anyone can access this' };
  }

  @Get('user-only')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Only users with JWT' })
  @ApiResponse({
    status: 200,
    description: 'Returns a message for authenticated users',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - JWT required' })
  userOnly(@Request() req: any) {
    if (req.authType !== 'jwt') throw new Error('JWT required');
    return {
      message: `Hello ${req.user.name}!`,
      email: req.user.email,
      token_type: req.authType,
    };
  }

  @Get('service-only')
  //   @UseGuards(AuthGuard('x-api-key'))
  @ApiBearerAuth('api-key')
  //   @ApiHeader({
  //     name: 'X-API-KEY',
  //     description: 'API Key for service-to-service authentication',
  //   })
  @ApiOperation({ summary: 'Only services with API key' })
  @ApiResponse({
    status: 200,
    description: 'Returns a message for authenticated services',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - API Key required' })
  serviceOnly(@Request() req: any) {
    if (req.authType !== 'api-key') throw new Error('API Key required');
    return {
      message: `Hello ${req.user.name}!`,
      keyId: req.apiKey.id,
      token_type: req.authType,
    };
  }

  //   @Get('service-only')
  //   @ApiBearerAuth('api-key')
  //   @ApiOperation({ summary: 'Only services with API key' })
  //   serviceOnly(@Request() req: any) {
  //     if (req.authType !== 'api-key') throw new Error('API Key required');
  //     return {
  //       message: `Hello ${req.user.name}!`,
  //       keyId: req.apiKey.id,
  //       token_type: req.authType,
  //     };
  //   }

  @Get('both')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiHeader({
    name: 'X-API-KEY',
    description:
      'API Key for service-to-service authentication (alternative to JWT)',
  })
  @ApiOperation({ summary: 'Accepts either JWT or API Key' })
  @ApiResponse({
    status: 200,
    description: 'Returns a message for authenticated users or services',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - JWT or API Key required',
  })
  both(@Request() req: any) {
    return {
      message: 'You are authenticated!',
      type: req.authType,
      email: req.user.email,
    };
  }
}
