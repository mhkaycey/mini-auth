// import { Controller, Get, Request } from '@nestjs/common';
// import {
//   ApiTags,
//   ApiOperation,
//   ApiBearerAuth,
//   ApiHeader,
// } from '@nestjs/swagger';

import { Controller, Get, Request } from '@nestjs/common';

import { AppService } from './app.service';

@Controller('health')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHealth() {
    return this.appService.getHealthStatus();
  }
}
