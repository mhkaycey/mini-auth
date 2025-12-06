import {
  Controller,
  Post,
  Delete,
  Param,
  Body,
  Request,
  UseGuards,
} from '@nestjs/common';
import { KeysService } from './keys.service';
import { CreateKeyDto } from './dto/create-key.dto';
import { AuthGuard } from '@nestjs/passport';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
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
          name: 'Payment Service',
          preview: 'sk_550e...a1b2',
        },
      },
    },
  })
  create(@Request() req: { user: User }, @Body() dto: CreateKeyDto) {
    return this.keysService.create(req.user.id, dto.name, dto.expirationDays);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoke an API key' })
  @ApiResponse({ status: 200, description: 'Key revoked' })
  revoke(@Request() req: { user: User }, @Param('id') id: string) {
    return this.keysService.revoke(req.user.id, id);
  }
}
