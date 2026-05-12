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
    clientCertNotAfter?: string;
  };

  bootstrap: {
    channel: "stable" | "beta" | "pilot";
    capabilities: string[];
  };
}
