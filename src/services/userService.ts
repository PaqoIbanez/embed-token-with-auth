// src/services/userService.ts

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { AppDataSource } from '../data/data-source';
import { UserEntity } from '../data/user.entity'; // Importar la entidad User


interface User {
  id: number;
  email: string;
  passwordHash: string;
  role: 'teacher' | 'student';
  registrationId?: string;
}

export class AuthService {
  // Método de autenticación
  async authenticateUser( email: string, password: string ): Promise<string> {
    const userRepo = AppDataSource.getRepository( UserEntity ); // Obtener el repositorio de User
    const user = await userRepo.findOne( { where: { email } } ); // Buscar usuario por email

    if ( !user || !( await bcrypt.compare( password, user.passwordHash ) ) ) {
      throw new Error( 'Credenciales inválidas' );
    }

    return this.generateJWT( user ); // Generar y devolver el JWT
  }

  // Método para generar JWT
  private generateJWT( user: User ): string {
    return jwt.sign(
      {
        sub: user.id, // user.id es de tipo number
        email: user.email,
        role: user.role,
        registrationId: user.registrationId
      },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  }
}

// Mock temporal (reemplazar con conexión real a DB)
const mockUsers: User[] = [
  {
    id: 1,
    email: 'profesor@example.com',
    passwordHash: bcrypt.hashSync( 'password123', 10 ),
    role: 'teacher',
    registrationId: 'PROF-123'
  },
  {
    id: 2,
    email: 'alumno@example.com',
    passwordHash: bcrypt.hashSync( 'password123', 10 ),
    role: 'student',
    registrationId: 'STU-456'
  }
];