import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/auth/guards/auth.guard'
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly user: UserService) { }

    @UseGuards(AuthGuard)
    @Get('')
    async getUser(@Request() req): Promise<any> {
        const res = await this.user.getUser({ id: req.user.id })
        return res;
    }
}
