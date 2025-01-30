import { Request, Response, NextFunction } from 'express';

// Middleware global para manejar errores
export const errorHandler = (err: Error, _: Request, res: Response, __: NextFunction) => {
  console.error("[ErrorHandler] Error:", err);
  if (res.headersSent) {
    return;
  }
  res.status(500).json({
    mensaje: "Error inesperado en el servidor",
    error: err.message,
  });
};
