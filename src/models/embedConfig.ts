// Modelo para la configuración de incrustación
export class EmbedConfig {
  constructor(
    public type: string,
    public reportsDetail: PowerBiReportDetails[],
    public embedToken: EmbedToken
  ) {}
}

// Modelo para detalles del reporte de Power BI
export class PowerBiReportDetails {
  constructor(
    public reportId: string,
    public reportName: string,
    public embedUrl: string,
    public datasetId: string
  ) {}
}

// Modelo para el token de incrustación
export interface EmbedToken {
  token: string;
  expiration: Date;
}
