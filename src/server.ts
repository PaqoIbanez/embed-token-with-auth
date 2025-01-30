import "reflect-metadata";
import express, { Application, Request, Response } from "express";
import cors from 'cors';
import helmet from 'helmet';
import https from 'https';
import path from "path";
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';

// Config y DataSource
import { config } from "./config/config";
import { AppDataSource } from './data/data-source';

// Middlewares
import { errorHandler } from './middleware/errorHandler';
import { authMiddleware, AuthenticatedRequest } from './middleware/authMiddleware';
import { roleMiddleware } from './middleware/roleMiddleware';

// Services
import { getEmbedInfo } from "./services/embedService";
import { AuthService } from './services/authService';

dotenv.config();
const app: Application = express();
const port = process.env.PORT || 5303;
const serverUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;

// Límite de peticiones para prevenir ataques de fuerza bruta / DDoS
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,                // Límite de peticiones
  standardHeaders: true,
  legacyHeaders: false,
});

// Configurar middlewares globales
app.use(express.json());
app.use(helmet()); // Añade cabeceras de seguridad
app.use(cors({
  origin: config.allowedDomains,
  credentials: true,
}));

// Validación de dominio manual
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && !config.allowedDomains.includes(origin)) {
    return res.status(403).json({ error: 'Dominio no permitido' });
  }
  next();
});

// Rutas públicas
app.post('/login', apiLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const token = await new AuthService().authenticateUser(email, password);
    res.json({ token });
  } catch (error) {
    res.status(401).json({ error: 'Autenticación fallida' });
  }
});

// Rutas protegidas
app.get(
  '/getEmbedToken',
  apiLimiter,
  authMiddleware,
  roleMiddleware(['teacher', 'student']),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = req.user!;
      const result = await getEmbedInfo(user);
      if (result.status !== 200) {
        return res.status(result.status).json({ error: result.error });
      }
      res.status(200).json(result);
    } catch (error) {
      res.status(500).json({
        error: "Error interno del servidor",
        detalle: "No se pudo generar el token de incrustación",
      });
    }
  }
);

// Middleware global de manejo de errores
app.use(errorHandler);

// Función para inicializar el servidor
async function initializeServer() {
  try {
    await AppDataSource.initialize();
    console.log('[TypeORM] Conexión a la base de datos establecida');

    // (Opcional) Crear un usuario por defecto solo en desarrollo
    if (process.env.NODE_ENV !== 'production') {
      const userRepo = AppDataSource.getRepository('UserEntity');
      const existingUser = await userRepo.findOne({ where: { email: 'profesor@example.com' } });
      if (!existingUser) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const bcrypt = require('bcrypt');
        const user = {
          email: 'profesor@example.com',
          passwordHash: await bcrypt.hash('password123', 10),
          role: 'teacher',
          registrationId: 'PROF-123',
        };
        await userRepo.save(user);
        console.log('[Seeder] Usuario "profesor@example.com" creado para pruebas');
      }
    }

    // Iniciar servidor
    if (config.httpsOptions) {
      https.createServer(config.httpsOptions, app).listen(443, () => {
        console.log(`[Server] Servidor HTTPS escuchando en puerto 443`);
      });
    } else {
      app.listen(port, () => {
        console.log(`[Server] Servidor HTTP en ${serverUrl}`);
      });
    }
  } catch (error) {
    console.error('[TypeORM] Error al conectar con la base de datos:', error);
    process.exit(1);
  }
}

// Arrancamos la inicialización
initializeServer();
