import {
  Body,
  Controller,
  Get,
  Post,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from 'src/guards/cutom.guard';
import { VerifyDto } from './dto/verify.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    const { access_token } = await this.authService.login(user, req.session);

    res.setHeader('Authorization', `Bearer ${access_token}`);
    return res.send({ message: 'Login successful', access_token });
  }

  @Post('register')
  async register(@Body() registerDto: RegisterDto, @Res() res: Response) {
    try {
      const user = await this.authService.register(
        registerDto.email,
        registerDto.password,
      );
      return res.redirect('verify');
    } catch (error) {
      console.error('Registration error:', error); // Log the error for debugging
      return res
        .status(500)
        .send({ message: 'Registration failed', error: error.message });
    }
  }

  @Post('verify')
  async verifyCode(@Body() verifyDto: VerifyDto, @Res() res: Response) {
    const isVerified = await this.authService.verifyCode(
      verifyDto.email,
      verifyDto.code,
    );
    if (isVerified) {
      await this.authService.storeDatabaseConnectionDetails(verifyDto.email);
      const user = await this.authService.findByEmail(verifyDto.email); // Fetch user details
      const token = await this.authService.login(user, {}); // Generate token
      return res.redirect(`/profile?token=${token.access_token}`); // Redirect to profile with token
    }
    return res
      .status(400)
      .send({ message: 'Invalid or expired verification code' });
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Req() req: Request) {
    return req.user;
  }
}
