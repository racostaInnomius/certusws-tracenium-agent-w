// src/domain/normalize-app.ts
import crypto from "crypto";
import {
  normalizeSoftwareDisplayMetadata,
  type SoftwareDisplayCategory
} from "./software-display-normalizer.js";

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
  displayName?: string;
  version?: string;
  publisher?: string;
  displayPublisher?: string;
  source: string;
  installLocation?: string;
  packageFamilyName?: string;
  installId: string;
  detectedAtUtc: string;
  rawName?: string;
  rawPublisher?: string;
  userFacing?: boolean;
  category?: SoftwareDisplayCategory;
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
  source: string;
  packageFamilyName?: string;
  publisher?: string;
}): string {
  const base = [
    (data.name || "").toLowerCase(),
    (data.publisher || "").toLowerCase(),
    data.packageFamilyName || "",
    (data.source || "").toLowerCase()
  ].join("|");

  const hash = crypto
    .createHash("sha256")
    .update(base)
    .digest("hex");

  return `sha256:${hash}`;
}

export function normalizeApp(input: RawAppInput): SoftwareApplication | null {
  const rawName = cleanString(input.name);
  const normalizedIdentityName = rawName?.toLowerCase();
  if (!rawName) return null;

  const version = cleanString(input.version);
  const rawPublisher = normalizePublisher(input.publisher);
  const installLocation = cleanString(input.installLocation);
  const packageFamilyName = cleanString(input.packageFamilyName);
  const source = input.source.toLowerCase();

  const display = normalizeSoftwareDisplayMetadata({
    name: rawName,
    publisher: cleanString(input.publisher),
    source,
    installLocation,
    packageFamilyName
  });

  const detectedAtUtc = new Date().toISOString();

  const installId = generateInstallId({
    name: normalizedIdentityName || rawName,
    source,
    packageFamilyName,
    publisher: rawPublisher
  });

  return {
    name: display.displayName,
    displayName: display.displayName,
    version,
    publisher: display.displayPublisher,
    displayPublisher: display.displayPublisher,
    source,
    installLocation,
    packageFamilyName,
    installId,
    detectedAtUtc,
    rawName,
    rawPublisher,
    userFacing: display.userFacing,
    category: display.category
  };
}