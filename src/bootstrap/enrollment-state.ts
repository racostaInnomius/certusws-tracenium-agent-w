// src/bootstrap/enrollment-state.ts
export interface EnrollmentState {
  tenantId: string;
  deviceId: string;

  enrolledAtUtc: string;
  lastRenewedAtUtc?: string;

  mtls: {
    clientCertPath: string;
    caBundlePath: string;
  };

  bootstrap: {
    channel: "stable" | "beta" | "pilot";
    capabilities: string[];
  };
}