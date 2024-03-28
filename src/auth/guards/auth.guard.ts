import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaClient, TOKEN_TYPE } from "@prisma/client";

const prisma = new PrismaClient();

const secretKey = process.env.JWT_ACCESS_TOKEN_SECRET
@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractAccessTokenFromCookie(request);
        if (!token) {
            throw new UnauthorizedException();
        }
        try {
            const payload = await this.jwtService.verifyAsync(
                token,
                {
                    secret: secretKey
                }
            );
            // 💡 We're assigning the payload to the request object here
            const user = await prisma.user.findUnique({ where: { id: payload.id } })
            // so that we can access it in our route handlers
            if(!user) throw new UnauthorizedException()
            request['user'] = user;
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }

    private extractAccessTokenFromCookie(request: Request): string | undefined {
        const token = request.cookies['__access'];
        return token ? token : undefined;
    }
}
