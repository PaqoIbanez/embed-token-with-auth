import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";
import { config } from "../config/config";

interface MsalConfig {
  auth: {
    clientId: string;
    authority: string;
    clientSecret: string;
  };
  system: {
    loggerOptions: {
      loggerCallback: (loglevel: LogLevel, message: string) => void;
      piiLoggingEnabled: boolean;
      logLevel: LogLevel;
    };
  };
}

const msalConfig: MsalConfig = {
  auth: {
    clientId: config.clientId,
    authority: `${config.authorityUrl}${config.tenantId}`,
    clientSecret: config.clientSecret,
  },
  system: {
    loggerOptions: {
      loggerCallback: (loglevel, message) => {
        // Podrías controlar el nivel de log para mayor seguridad
        console.log(`[MSAL] ${message}`);
      },
      piiLoggingEnabled: false,
      logLevel: LogLevel.Verbose,
    },
  },
};

// Exportamos una única instancia del cliente confidencial
export const msalClient = new ConfidentialClientApplication(msalConfig);

export const getAccessToken = async () => {
  try {
    const tokenResponse = await msalClient.acquireTokenByClientCredential({
      scopes: [config.scopeBase],
    });

    if (!tokenResponse?.accessToken) {
      throw new Error("Error al obtener token de acceso (Power BI).");
    }

    return {
      accessToken: tokenResponse.accessToken,
      expiresOn: tokenResponse.expiresOn || new Date(),
    };
  } catch (error) {
    console.error("[MSAL] Error al obtener el token de acceso:", error);
    throw error;
  }
};
