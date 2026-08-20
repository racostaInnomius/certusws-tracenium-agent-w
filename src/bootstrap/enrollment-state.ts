// src/bootstrap/enrollment-state.ts
export interface EnrollmentState {
  tenantId: string;
  deviceId: string;

  enrolledAtUtc: string;
  lastRenewedAtUtc?: string;

  mtls: {
    clientCertPath: string;
    caBundlePath: string;
    clientCertThumbprint?: string;
    issuingCaThumbprint?: string;
    /**
     * Todas las CA intermedias del bundle instalado. El agente de Windows
     * exige que la cadena del servidor contenga AL MENOS una: con un valor
     * único, rotar la CA emisora desconecta al parque entero y sin recurso.
     */
    issuingCaThumbprints?: string[];
    clientCertNotAfter?: string;
  };

  bootstrap: {
    channel: "stable" | "beta" | "pilot";
    capabilities: string[];
  };
}
