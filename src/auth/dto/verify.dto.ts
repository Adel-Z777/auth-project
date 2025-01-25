import { IsEmail, IsNotEmpty } from 'class-validator';

export class VerifyDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  code: string;
}
