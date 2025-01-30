import { NextFunction, Response } from 'express';
import { AuthenticatedRequest } from './authMiddleware';

// Middleware para verificar que el rol del usuario esté en la lista permitida
export const roleMiddleware = ( allowedRoles: string[] ) => {
  return ( req: AuthenticatedRequest, res: Response, next: NextFunction ) => {
    if ( !req.user?.role || !allowedRoles.includes( req.user.role ) ) {
      return res.status( 403 ).json( { error: 'Acceso prohibido: rol no autorizado' } );
    }
    next();
  };
};