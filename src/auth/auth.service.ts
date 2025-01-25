import { Injectable, UnauthorizedException, ConflictException, InternalServerErrorException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.entity';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  private verificationAttempts: { [key: string]: { attempts: number; lastAttempt: Date } } = {};

  constructor(
    private jwtService: JwtService,
    private userService: UserService,
  ) {}

  async register(email: string, password: string): Promise<User> {
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit code
    const hashedVerificationCode = await bcrypt.hash(verificationCode, 10); // Hash the verification code
    const verificationCodeExpires = new Date();
    verificationCodeExpires.setMinutes(verificationCodeExpires.getMinutes() + 15); // Set expiration to 15 minutes

    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User();
    user.email = email;
    user.password = hashedPassword;

    user.verificationCode = hashedVerificationCode; // Store hashed verification code
    user.verificationCodeExpires = verificationCodeExpires; // Store expiration timestamp

    try {
        // Send verification email
        await this.sendVerificationEmail(email, verificationCode); // Implement this method

      return await this.userService.save(user);
    } catch (error) {
      console.error('Error saving user:', error);
      throw new InternalServerErrorException('Failed to save user');
    }
  }

  async sendVerificationEmail(email: string, verificationCode: string) {
    const transporter = nodemailer.createTransport({
        host: 'smtp.example.com', // Replace with your SMTP server
        port: 587, // Replace with your SMTP port
        secure: false, // true for 465, false for other ports
        auth: {
            user: 'your-email@example.com', // Replace with your email
            pass: 'your-email-password', // Replace with your email password
        },
    });

    const mailOptions = {
        from: '"Your App" <your-email@example.com>', // Sender address
        to: email, // List of recipients
        subject: 'Email Verification', // Subject line
        text: `Your verification code is: ${verificationCode}`, // Plain text body
    };

    await transporter.sendMail(mailOptions);
  }

  async verifyCode(email: string, code: string): Promise<boolean> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const currentTime = new Date();
    const attemptsInfo = this.verificationAttempts[email] || { attempts: 0, lastAttempt: null };

    // Check for cooldown period
    if (attemptsInfo.attempts >= 5 && attemptsInfo.lastAttempt) {
      const cooldownPeriod = 5 * 60 * 1000; // 5 minutes
      if (currentTime.getTime() - attemptsInfo.lastAttempt.getTime() < cooldownPeriod) {
        throw new UnauthorizedException('Too many attempts. Please try again later.');
      } else {
        // Reset attempts after cooldown
        attemptsInfo.attempts = 0;
      }
    }

    const isCodeValid = await bcrypt.compare(code, user.verificationCode);
    const isExpired = currentTime > user.verificationCodeExpires;

    if (isCodeValid && !isExpired) {
      user.verificationCode = null; // Clear the verification code
      user.verificationCodeExpires = null; // Clear the expiration timestamp
      user.isVerified = true; // Mark user as verified
      await this.userService.save(user);
      return true;
    }

    // Increment attempts
    attemptsInfo.attempts += 1;
    attemptsInfo.lastAttempt = currentTime;
    this.verificationAttempts[email] = attemptsInfo;

    throw new UnauthorizedException('Invalid or expired verification code');
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async login(user: User, session: any) {
    const payload = { email: user.email, id: user.uuid };
    const token = this.jwtService.sign(payload);
    
    // Store the token in the session
    session.token = token;

    return { access_token: token };
  }

  async getProfile(uuid: string): Promise<User | null> {
    const user = await this.userService.findById(uuid);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }
}
