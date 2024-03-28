/* eslint-disable prettier/prettier */
// src/user/dto/user.dto.ts
import { IsEmail, isEnum, IsMongoId, isNotEmpty, IsNotEmpty, IsOptional, IsString} from 'class-validator';

export class GetUserDto {
  @IsNotEmpty()
  @IsMongoId()
  id: string;
}
