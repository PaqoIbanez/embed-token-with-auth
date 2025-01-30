import "express";

declare module "express-serve-static-core" {
  interface Request {
    // Si en algún momento necesitas más información de autenticación
    authContext?: {
      accessToken: string;
      expiresOn: Date;
    };
  }
}
