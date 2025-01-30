import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity({ schema: 'public', name: 'users' })
export class UserEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  passwordHash: string;

  @Column({ type: 'enum', enum: ['teacher', 'student'] })
  role: 'teacher' | 'student';

  @Column({ nullable: true })
  registrationId?: string;
}
