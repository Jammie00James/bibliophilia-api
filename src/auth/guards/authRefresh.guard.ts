import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaClient, TOKEN_TYPE } from "@prisma/client";
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

const secretKey = process.env.JWT_ACCESS_TOKEN_SECRET
@Injectable()
export class AuthRefreshGuard implements CanActivate {
    constructor(private jwtService: JwtService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractRefreshTokenFromCookie(request);
        if (!token) throw new UnauthorizedException();
        const payload = await this.jwtService.verifyAsync(
            token,
            {
                secret: secretKey
            }
        );
        // 💡 We're assigning the payload to the request object here
        if (!payload) throw new UnauthorizedException();

        const hashTokens = await prisma.token.findMany({
            where: {
                user_Id: payload.id,
                type: TOKEN_TYPE.refresh_token_hash
            }
        })

        if (hashTokens.length < 1) throw new UnauthorizedException('invalid token_')
        // Check if the reset link is still valid
        const currentDateTime = new Date();
        let isValid: boolean
        for (const hashToken of hashTokens) {
            if (hashToken.expire_at <= currentDateTime) {
                await prisma.token.delete({
                    where: {
                        id: hashToken.id
                    }
                });
                throw new UnauthorizedException('expired token')
            }
            isValid = await bcrypt.compare(payload.token, hashToken.token)
            if (isValid) break
        }
        if (!isValid) throw new UnauthorizedException("invalid token")

        // so that we can access it in our route handlers
        const user = await prisma.user.findUnique({
            where: {
                id: payload.id
            }
        })
        request['user'] = user;
        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }

    private extractRefreshTokenFromCookie(request: Request): string | undefined {
        const token = request.cookies['__refresh'];
        return token ? token : undefined;
    }
}
