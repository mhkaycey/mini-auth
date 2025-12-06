import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional, IsInt, Min } from 'class-validator';

export class CreateKeyDto {
  @ApiProperty({ example: 'Payment Service', required: true })
  @IsString()
  name: string;

  @ApiProperty({ example: 90, required: false, default: 90 })
  @IsOptional()
  @IsInt()
  @Min(1)
  expirationDays?: number;
}
