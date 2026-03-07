// src/domain/normalize-app.ts
import crypto from "crypto";

export interface RawAppInput {
  name?: string | null;
  version?: string | null;
  publisher?: string | null;
  source: string;
  installLocation?: string | null;
  packageFamilyName?: string | null;
}

export interface SoftwareApplication {
  name: string;
  version?: string;
  publisher?: string;
  source: string;
  installLocation?: string;
  packageFamilyName?: string;
  installId: string;
  detectedAtUtc: string;
}

function cleanString(value?: string | null): string | undefined {
  if (!value) return undefined;

  const cleaned = value
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.length > 0 ? cleaned : undefined;
}

function normalizePublisher(publisher?: string | null): string | undefined {
  if (!publisher) return undefined;

  const p = cleanString(publisher);
  if (!p) return undefined;

  return p.toLowerCase();
}

export function generateInstallId(data: {
  name: string;
  version?: string;
  publisher?: string;
  source: string;
  installLocation?: string;
  packageFamilyName?: string;
}): string {
  const base = [
    data.name || "",
    data.version || "",
    data.publisher || "",
    data.source || "",
    data.installLocation || "",
    data.packageFamilyName || ""
  ].join("|");

  const hash = crypto
    .createHash("sha256")
    .update(base)
    .digest("hex");

  return `sha256:${hash}`;
}

export function normalizeApp(input: RawAppInput): SoftwareApplication | null {
  const name = cleanString(input.name);
  if (!name) return null;

  const version = cleanString(input.version);
  const publisher = normalizePublisher(input.publisher);
  const installLocation = cleanString(input.installLocation);
  const packageFamilyName = cleanString(input.packageFamilyName);

  const detectedAtUtc = new Date().toISOString();

  const installId = generateInstallId({
    name,
    version,
    publisher,
    source: input.source,
    installLocation,
    packageFamilyName
  });

  return {
    name,
    version,
    publisher,
    source: input.source as any,
    installLocation,
    packageFamilyName,
    installId,
    detectedAtUtc
  };
}