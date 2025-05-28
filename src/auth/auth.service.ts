import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from 'generated/prisma';
import { RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  async onModuleInit() {
    await this.$connect();
    this.logger.log('MongoDB connected successfully');
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: { email },
      });
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists with this email',
        });
      }
      const newUser = await this.user.create({
        data: {
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = newUser;
      return {
        user: userWithoutPassword,
        token: 'dummy-token',
      };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to register user';

      throw new RpcException({
        status: 400,
        message: errorMessage,
      });
    }
  }
}
