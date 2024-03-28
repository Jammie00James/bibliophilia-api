import { Injectable, NotFoundException } from '@nestjs/common';
import { GetUserDto } from './dto/user.dto';
import { PrismaClient,  TOKEN_TYPE } from "@prisma/client";


const prisma = new PrismaClient()

@Injectable()
export class UserService {

    async getUser(getUserDto:GetUserDto): Promise<object>{
        const user = await prisma.user.findUnique({
            where:{
                id: getUserDto.id
            },
            select:{
                id:true,
                username:true,
                email:true,
                role:true,
                emailConfirmed:true,
                disabled:true,
                created_at:true

            }
        })

        if(!user) throw new NotFoundException('user not found')

        return user
    }

}
