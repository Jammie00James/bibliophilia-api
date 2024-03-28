/* eslint-disable prettier/prettier */
// src/users/dto/user.dto.ts
import { IsEmail,IsMongoId, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class RegisterDto {
    @IsNotEmpty()
    @IsString()
    username: string;

    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;

    @IsNotEmpty()
    @IsString()
    confirmPassword: string;

}

export class LoginDto {
    @IsNotEmpty()
    @IsString()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;
}

export class SendConfirmEmailDto {
    @IsNotEmpty()
    @IsEmail()
    email: string;
}

export class GenerateAuthTokensDto {
    @IsNotEmpty()
    @IsMongoId()
    id: string;
}

export class RefreshDto {
    @IsNotEmpty()
    @IsMongoId()
    id: string;
}

export class ForgotPasswordDto {
    @IsNotEmpty()
    @IsEmail()
    email: string;
}

export class VerifyEmailDto {
    @IsNotEmpty()
    @IsString()
    token: string;
}

export class ChangePasswordDto {
    @IsNotEmpty()
    @IsString()
    token: string;

    @IsNotEmpty()
    @IsString()
    password:string

    @IsNotEmpty()
    @IsString()
    confirmPassword:string
}

