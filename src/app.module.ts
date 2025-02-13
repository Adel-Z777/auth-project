import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { UserService } from './user/user.service';
import { TypeOrmModule } from '@nestjs/typeorm'; // Re-import TypeOrmModule
import { DataSource } from 'typeorm'; // Import DataSource
import { User } from './user/user.entity';
import { JwtModule } from '@nestjs/jwt';

const dataSource = new DataSource({
  type: 'postgres', // Database type
  host: 'localhost',
  port: 5432, // Database port
  username: 'postgres', // Database username
  password: 'password', // Database password
  database: 'users', // Updated database name
  entities: [User],
  synchronize: true, // Set to false in production
});

@Module({
  imports: [
    TypeOrmModule.forRoot(dataSource.options), // Use DataSource options
    TypeOrmModule.forFeature([User]),
    JwtModule.register({
      secret: 'your_secret_key', // Replace with your actual secret key
      signOptions: { expiresIn: '60s' }, // Token expiration time
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, UserService],
})
export class AppModule {}
