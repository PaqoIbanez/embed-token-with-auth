import "express";

declare module "express-serve-static-core" {
  interface Request {
    authContext?: {
      accessToken: string;
      expiresOn: Date;
    };
  }
}