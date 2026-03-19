// src/platform/platform.ts
import os from "os";

import { getDeviceId as _getDeviceId } from "./device-id";
import { getPrivSvcPipePath as _getPrivSvcPipePath } from "./privsvc-path";
import { writeEnrollmentMetadata as _writeEnrollmentMetadata } from "./enrollment-meta";

export type EnrollmentMetadata = {
  tenantId: string;
  enrolledAtUtc: string;
  agentVersion: string;
};

export function getPlatform(): string {
  return os.platform();
}

export function getDeviceId(): string {
  return _getDeviceId();
}

export function getPrivSvcSocket(): string {
  return _getPrivSvcPipePath();
}

export async function writeEnrollmentMeta(meta: EnrollmentMetadata): Promise<void> {
  return _writeEnrollmentMetadata(meta);
}