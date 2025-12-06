// import { Controller, Get, Request } from '@nestjs/common';
// import {
//   ApiTags,
//   ApiOperation,
//   ApiBearerAuth,
//   ApiHeader,
// } from '@nestjs/swagger';

// @ApiTags('Demo Routes')
// @Controller()
// export class AppController {
//   @Get('public')
//   @ApiOperation({ summary: 'Public endpoint – no auth' })
//   public() {
//     return { message: 'Anyone can access this' };
//   }

//   @Get('user-only')
//   @ApiBearerAuth('JWT-auth')
//   @ApiOperation({ summary: 'Only users with JWT' })
//   userOnly(@Request() req: any) {
//     if (req.authType !== 'jwt') throw new Error('JWT required');
//     return { message: 'Hello user!', email: req.user.email };
//   }

//   @Get('service-only')
//   @ApiHeader({ name: 'X-API-KEY', description: 'API Key' })
//   @ApiOperation({ summary: 'Only services with API key' })
//   serviceOnly(@Request() req: any) {
//     if (req.authType !== 'api-key') throw new Error('API Key required');
//     return { message: 'Hello service!', keyId: req.apiKey.id };
//   }

//   @Get('both')
//   @ApiOperation({ summary: 'Accepts either JWT or API Key' })
//   both(@Request() req: any) {
//     return {
//       message: 'You are authenticated!',
//       type: req.authType,
//       email: req.user.email,
//     };
//   }
// }
import { Controller, Get } from '@nestjs/common';

import { AppService } from './app.service';

@Controller('health')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHealth() {
    return this.appService.getHealthStatus();
  }
}
