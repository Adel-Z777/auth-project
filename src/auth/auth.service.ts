import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import { DataSource } from 'typeorm'; // Import DataSource from TypeORM
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.entity';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  private verificationAttempts: {
    [key: string]: { attempts: number; lastAttempt: Date };
  } = {};
  private dataSource: DataSource; // Declare DataSource instance

  constructor(
    private jwtService: JwtService,
    private userService: UserService,
  ) {
    this.dataSource = new DataSource({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'password',
      database: 'users', // Default database name
      entities: [User],
      synchronize: true,
    });
  }

  async register(email: string, password: string): Promise<User> {
    const databaseName = `db_${email.replace('@', '_').replace('.', '_')}`; // Generate a unique database name
    await this.createDatabase(databaseName); // Call the method to create a new database

    const verificationCode = Math.floor(
      100000 + Math.random() * 900000,
    ).toString(); // Generate a 6-digit code
    const hashedVerificationCode = await bcrypt.hash(verificationCode, 10); // Hash the verification code
    const verificationCodeExpires = new Date();
    verificationCodeExpires.setMinutes(
      verificationCodeExpires.getMinutes() + 5,
    ); // Set expiration to 5 minutes

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
      await this.sendVerificationEmail(email, verificationCode); // Implement this method
      return await this.userService.save(user);
    } catch (error) {
      console.error('Error creating database:', error); // Log any errors during database creation
      console.error('Error saving user:', error);
      throw new InternalServerErrorException('Failed to save user');
    }
  }

  async createDatabase(databaseName: string): Promise<void> {
    if (!this.dataSource.isInitialized) {
      await this.dataSource.initialize(); // Initialize the DataSource only if not already initialized
    }
    await this.dataSource.query(`CREATE DATABASE "${databaseName}"`);
    await this.dataSource.destroy(); // Close the connection after creating the database
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userService.findByEmail(email);
  }

  async sendVerificationEmail(email: string, verificationCode: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: '',
        pass: '',
      },
    });

    const mailOptions = {
      from: 'Winoptic', // Sender address
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

    const isCodeValid = await bcrypt.compare(code, user.verificationCode);
    const isExpired = new Date() > user.verificationCodeExpires;

    if (isCodeValid && !isExpired) {
      user.verificationCode = null; // Clear the verification code
      user.verificationCodeExpires = null; // Clear the expiration timestamp
      user.isVerified = true; // Mark user as verified
      await this.storeDatabaseConnectionDetails(email); // Store connection details after verification
      await this.userService.save(user);
      return true;
    }

    throw new UnauthorizedException('Invalid or expired verification code');
  }

  async storeDatabaseConnectionDetails(email: string): Promise<void> {
    const user = await this.userService.findByEmail(email);
    if (user) {
      user.databaseName = `db_${email.replace('@', '_').replace('.', '_')}`;
      user.host = 'localhost';
      user.username = 'postgres';
      user.password = 'password'; // Store the password securely
      await this.userService.save(user);
    }
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
