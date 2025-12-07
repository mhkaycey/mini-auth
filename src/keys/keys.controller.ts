import {
  Controller,
  Post,
  Delete,
  Param,
  Body,
  Request,
  UseGuards,
  HttpCode,
  HttpStatus,
  Get,
} from '@nestjs/common';
import { KeysService } from './keys.service';
import { CreateKeyDto } from './dto/create-key.dto';
import { AuthGuard } from '@nestjs/passport';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiHeader,
} from '@nestjs/swagger';
import { User } from '../auth/jwt.strategy';

@ApiTags('API Keys')
@Controller('keys')
@UseGuards(AuthGuard('jwt'))
@ApiBearerAuth('JWT-auth')
export class KeysController {
  constructor(private keysService: KeysService) {}

  @Post('create')
  @ApiOperation({ summary: 'Create a new API key (JWT required)' })
  @ApiResponse({
    status: 201,
    description: 'API key created – SAVE IT NOW!',
    schema: {
      example: {
        message: 'API Key created — save it now!',
        apiKey: 'sk_550e...a1b2',
        details: {
          id: 'uuid',
          name: 'Payment API',
          preview: 'sk_550e...a1b2',
        },
      },
    },
  })
  create(@Request() req: { user: User }, @Body() dto: CreateKeyDto) {
    return this.keysService.create(req.user.id, dto.name, dto.expirationDays);
  }

  @Delete(':id')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke an API key' })
  @ApiResponse({ status: 204, description: 'API key revoked successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'API key not found' })
  revoke(@Request() req: { user: User }, @Param('id') id: string) {
    return this.keysService.revoke(req.user.id, id);
  }

  @Get('validate')
  @UseGuards(AuthGuard('jwt'))
  @ApiHeader({
    name: 'X-API-KEY',
    description: 'API Key for service-to-service authentication',
  })
  @ApiOperation({ summary: 'Validate an API key' })
  @ApiResponse({ status: 200, description: 'API key is valid' })
  @ApiResponse({ status: 401, description: 'Invalid or expired API key' })
  async validateApiKey(@Request() req) {
    return {
      valid: true,
      user: {
        id: req.user.id,
        email: req.user.email,
      },
      apiKey: {
        id: req.apiKey.id,
        name: req.apiKey.name,
        expiresAt: req.apiKey.expiresAt,
      },
    };
  }
}
