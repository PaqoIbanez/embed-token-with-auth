import "reflect-metadata";
import { DataSource } from 'typeorm';
import { UserEntity } from './user.entity';
import dotenv from 'dotenv';

dotenv.config();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER || 'alumno',
  password: process.env.DB_PASSWORD || '123456',
  database: process.env.DB_NAME || 'course-db',
  entities: [UserEntity],
  synchronize: true, // Solo recomendado para desarrollo
  logging: false,    // Desactiva logs detallados en producción
});
