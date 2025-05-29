import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from 'generated/prisma';
import { RegisterUserDto, LoginUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('MongoDB connected successfully');
  }

  signJWT(payload: JwtPayload) {
    return this.jwtService.signAsync(payload);
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

      const token = await this.signJWT({
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
      });

      return {
        user: userWithoutPassword,
        token,
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

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }
      const isPasswordValid = bcrypt.compareSync(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = user;

      const token = await this.signJWT({
        id: user.id,
        email: user.email,
        name: user.name,
      });

      return {
        user: userWithoutPassword,
        token,
      };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed login user';

      throw new RpcException({
        status: 400,
        message: errorMessage,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } =
        await this.jwtService.verifyAsync(token, {
          secret: envs.jwtSecret,
        },
      );
      if (!user) {
        throw new RpcException({
          status: 401,
          message: 'Invalid token',
        });
      }
      const newToken = await this.signJWT(user);

      return {
        user,
        token: newToken,
      };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to verify token';

      throw new RpcException({
        status: 401,
        message: errorMessage,
      });
    }
  }
}
