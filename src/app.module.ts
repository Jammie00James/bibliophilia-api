import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MailModule } from './mail/mail.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [AuthModule,PassportModule.register({ defaultStrategy: 'jwt' }), MailModule, UserModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
