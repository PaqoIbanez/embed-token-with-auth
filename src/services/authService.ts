import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { AppDataSource } from '../data/data-source';
import { UserEntity } from '../data/user.entity';

interface User {
  id: number;
  email: string;
  passwordHash: string;
  role: 'teacher' | 'student';
  registrationId?: string;
}

export class AuthService {
  // Autentica al usuario mediante email y password
  async authenticateUser(email: string, password: string): Promise<string> {
    const userRepo = AppDataSource.getRepository(UserEntity);
    const user = await userRepo.findOne({ where: { email } });

    if (!user) {
      throw new Error('Usuario no encontrado.');
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      throw new Error('Contraseña incorrecta.');
    }

    // Generamos y devolvemos el token JWT
    return this.generateJWT(user);
  }

  // Genera un token JWT con datos relevantes del usuario
  private generateJWT(user: User): string {
    return jwt.sign(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        registrationId: user.registrationId,
      },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  }
}
