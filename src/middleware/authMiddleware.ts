import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';

export interface AuthenticatedRequest extends Request {
  user?: {
    email: string;
    role: 'teacher' | 'student';
    registrationId?: string;
  };
}

// Verifica que el token JWT sea válido y adjunta la información del usuario a req.user
export const authMiddleware = ( req: AuthenticatedRequest, res: Response, next: NextFunction ) => {
  try {

    // EJEMPLO (versión nueva):
    const token = req.cookies?.token;
    if ( !token ) {
      return res.status( 401 ).json( { error: 'Acceso no autorizado, falta token' } );
    }
    // jwt.verify(token)
    // set req.user


    const decoded = jwt.verify( token, config.jwtSecret ) as jwt.JwtPayload;
    req.user = {
      email: decoded.email,
      role: decoded.role,
      registrationId: decoded.registrationId,
    };

    next();
  } catch ( error ) {
    res.status( 401 ).json( { error: 'Token inválido o expirado' } );
  }
};
