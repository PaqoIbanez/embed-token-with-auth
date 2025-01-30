import axios, { AxiosError } from "axios";
import { config } from "../config/config";
import { PowerBiReportDetails } from "../models/embedConfig";
import { getAccessToken } from "./msalClient";

interface AuthenticatedUser {
  email: string;
  role: 'teacher' | 'student';
  registrationId?: string;
}

// Principal método para que el frontend obtenga la información de incrustación
export const getEmbedInfo = async ( user: AuthenticatedUser ) => {
  try {
    const reportDetails = await getReportDetails();
    const embedToken = await generateEmbedToken( reportDetails, user );

    // Devuelve los datos necesarios para incrustar el reporte
    return {
      accessToken: embedToken.token,
      embedUrl: reportDetails.embedUrl,
      expiry: embedToken.expiration,
      status: 200,
    };
  } catch ( error ) {
    const axiosError = error as AxiosError;
    // console.error( "[EmbedService] Error al obtener información de incrustación:", axiosError.message );
    return {
      status: 500,
      error: `Error interno al procesar la solicitud ${ error }`,
    };
  }
};

// Obtiene los detalles del reporte (embedUrl, nombre, etc.)
const getReportDetails = async () => {

  const url = `${ config.powerBiApiUrl }v1.0/myorg/groups/${ config.workspaceId }/reports/${ config.reportId }`;
  const headers = await getAuthHeaders();
  const response = await axios.get( url, { headers } );

  if ( !response.data.embedUrl ) {
    throw new Error( "URL de incrustación no disponible en la respuesta de Power BI" );
  }

  return new PowerBiReportDetails(
    response.data.id,
    response.data.name,
    response.data.embedUrl,
    response.data.datasetId
  );
};

// Genera el token de incrustación usando el rol y email del usuario
const generateEmbedToken = async ( report: PowerBiReportDetails, user: AuthenticatedUser ) => {

  const url = `${ config.powerBiApiUrl }v1.0/myorg/GenerateToken`;
  const headers = await getAuthHeaders();

  // Define roles específicos según el rol de la aplicación
  const roleForRLS =
    user.role === 'teacher'
      ? 'FiltroMentor'
      : 'FiltroAlumno';

  const body = {
    reports: [ { id: report.reportId, groupId: config.workspaceId } ],
    datasets: [ { id: report.datasetId } ],
    identities: [
      {
        username: user.email,
        roles: [ roleForRLS ],
        datasets: [ report.datasetId ],
      },
    ],
  };

  const response = await axios.post( url, body, { headers } );
  return {
    token: response.data.token,
    expiration: new Date( response.data.expiration ),
  };
};

// Retorna las cabeceras de autenticación para llamar a la API de Power BI
const getAuthHeaders = async () => {
  const { accessToken } = await getAccessToken();
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${ accessToken }`,
  };
};
