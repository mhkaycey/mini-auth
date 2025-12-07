import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { KeysModule } from 'src/keys/keys.module';
import { ExampleController } from './example.controller';

@Module({
  imports: [AuthModule, KeysModule],
  controllers: [ExampleController],
})
export class ExampleModule {}
