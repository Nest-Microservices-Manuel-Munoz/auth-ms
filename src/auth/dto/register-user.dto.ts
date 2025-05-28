import { IsEmail, IsString } from 'class-validator';

export class RegisterUserDto {
  @IsString()
  name: string;

  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  password: string;
}
