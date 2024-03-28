import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { MailService } from 'src/mail/mail.service';
import { UserService } from 'src/user/user.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [
  JwtModule.register({
    global: true,
    secret: process.env.JWT_ACCESS_TOKEN_SECRET,
    signOptions: { expiresIn: '15m' },
  }),
],
  controllers: [AuthController],
  providers: [AuthService, MailService, UserService]
})
export class AuthModule {}