import { Body, Controller, Get, Post, Request, Res, UseGuards, ValidationPipe } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { ChangePasswordDto, ForgotPasswordDto, LoginDto, RegisterDto } from './dto/auth.dto';
import { AuthGuard } from './guards/auth.guard';
import { AuthRefreshGuard } from './guards/authRefresh.guard';

@Controller('auth')
export class AuthController {

    constructor(private readonly auth: AuthService) { }

    @Post('register')
    async register(@Body(new ValidationPipe()) registerDto: RegisterDto) {
        try {
            const res = await this.auth.register(registerDto);
            return res;
        } catch (error) {
            console.log({ error });
            throw error;
        }
    }

    @Post('login')
    async login(@Body(new ValidationPipe()) loginDto: LoginDto, @Res() res: Response) {
        try {
            const result = await this.auth.logIn(loginDto);
            res.cookie('__access', result.tokens.accessToken, { httpOnly: false, secure: true, sameSite: 'none', maxAge: 900000 })
            res.cookie('__refresh', result.tokens.refreshToken, { httpOnly: false, secure: true, sameSite: 'none', maxAge: 259200000 })
            return res.send({ user: result.user });
        } catch (error) {
            console.log({ error });
            throw error;
        }
    }

    @Post('forgotpassword')
    async forgotPassword(@Body(new ValidationPipe()) forgotPasswordDto: ForgotPasswordDto) {
        try {
            const res = await this.auth.forgotPassword(forgotPasswordDto);
            return res;
        } catch (error) {
            console.log({ error });
            throw error;
        }
    }

    @Post('change-password')
    async changePassword(@Body(new ValidationPipe()) changePasswordDto: ChangePasswordDto) {
        try {
            const res = await this.auth.changePassword(changePasswordDto);
            return res;
        } catch (error) {
            console.log({ error });
            throw error;
        }
    }

    @UseGuards(AuthGuard)
    @Post('resendtoken')
    async resendToken(@Request() req): Promise<any> {
        const res = await this.auth.requestEmailVerification({ email: req.user.email })
        return res;
    }


    @UseGuards(AuthGuard)
    @Post('logout')
    async logout(@Request() req, @Res() res: Response): Promise<any> {
        const result = await this.auth.logout(req.user.id)
        res.cookie('__access', 'out', { httpOnly: false, secure: true, sameSite: 'none', maxAge: 1 })
        res.cookie('__refresh', 'out', { httpOnly: false, secure: true, sameSite: 'none', maxAge: 1 })
        return res.send(result);
    }

    @UseGuards(AuthRefreshGuard)
    @Get('refresh')
    async refresh(@Request() req, @Res() res: Response): Promise<any> {
        const user = req.user
        const result = await this.auth.refresh({ id: user.id })

        res.cookie('__access', result, { httpOnly: false, secure: true, sameSite: 'none', maxAge: 900000 })
        return res.send(result);
    }


    @Post('verify')
    async verifyUser(@Body() data: any) {
        const res = await this.auth.verifyEmail({ token: data.token })
        return res;
    }

    @UseGuards(AuthGuard)
    @Get('')
    async getUser(@Request() req): Promise<any> {
        const res = await this.auth.getUser({ id: req.user.id })
        return res;
    }
}
