import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  uuid: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  verificationCode: string;

  @Column({ type: 'timestamp', nullable: true })
  verificationCodeExpires: Date;

  @Column({ default: false }) // New field to track verification status
  isVerified: boolean; // Indicates if the user has verified their email

  // New fields for database connection details
  @Column({ nullable: true })
  databaseName: string;

  @Column({ nullable: true })
  host: string;

  @Column({ nullable: true })
  username: string;

  @Column({ nullable: true })
  dbPassword: string; // Renamed to avoid conflict
}
