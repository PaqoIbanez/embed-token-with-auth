import dotenv from 'dotenv';
import fs from 'fs';

// Cargar variables de entorno desde .env
dotenv.config();

interface Config {
  workspaceId: string;
  reportId: string;
  clientId: string;
  clientSecret: string;
  tenantId: string;
  authorityUrl: string;
  powerBiApiUrl: string;
  scopeBase: string;
  authenticationMode: "ServicePrincipal";
  embedUsername: string;
  embedRoles: string[];
  jwtSecret: string;
  allowedDomains: string[];
  httpsOptions?: {
    key: string;
    cert: string;
  };
}

// Usa las variables de entorno o valores por defecto en desarrollo
export const config: Config = {
  workspaceId: process.env.WORKSPACE_ID || "",
  reportId: process.env.REPORT_ID || "",
  clientId: process.env.CLIENT_ID || "",
  clientSecret: process.env.CLIENT_SECRET || "",
  tenantId: process.env.TENANT_ID || "",
  authorityUrl: "https://login.microsoftonline.com/",
  powerBiApiUrl: "https://api.powerbi.com/",
  scopeBase: "https://analysis.windows.net/powerbi/api/.default",
  authenticationMode: "ServicePrincipal",
  embedUsername: process.env.EMBED_USERNAME || "",
  embedRoles: [ "FiltroMatricula" ],
  jwtSecret: process.env.JWT_SECRET || '',
  allowedDomains: process.env.ALLOWED_DOMAINS?.split( ',' ) || [ 'http://localhost:3000' ],
  httpsOptions:
    process.env.NODE_ENV === 'production' &&
      process.env.SSL_KEY_PATH &&
      process.env.SSL_CERT_PATH
      ? {
        key: fs.readFileSync( process.env.SSL_KEY_PATH ).toString(),
        cert: fs.readFileSync( process.env.SSL_CERT_PATH ).toString(),
      }
      : undefined,
};
