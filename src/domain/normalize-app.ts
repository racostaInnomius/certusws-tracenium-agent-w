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

  // ── ADR-0019 F0 — la identidad para poder quitarlo ────────────────
  //
  // ⚠️ ESTA LISTA ES UN FILTRO, NO UNA DECLARACIÓN. Todo campo que no esté
  // aquí se pierde en silencio aunque el colector lo mande: el objeto que
  // construye el llamador se arma nombrando campos uno a uno, así que un
  // campo nuevo no da error de tipos ni de ejecución — simplemente no llega.
  //
  // El colector de Windows (`SoftwareInventory.cs`) llevaba estos cuatro
  // campos desde 1.1.65 y las cuatro columnas del backend seguían VACÍAS en
  // los 52 equipos que ya corrían esa versión, porque se caían aquí y en el
  // llamador. Es el mismo patrón de `uptimeSeconds` y `antivirus.products`.
  //
  // Sólo `win32-registry` los trae; los demás orígenes los dejan undefined,
  // que es la respuesta correcta y no un hueco: «no sabemos cómo quitarlo».
  uninstallString?: string | null;
  quietUninstallString?: string | null;
  productCode?: string | null;
  uninstallKeyPath?: string | null;
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

  // ADR-0019 F0. Se propagan tal cual: normalizar un ProductCode o un comando
  // de desinstalación sería estropearlos — se ejecutan literalmente.
  uninstallString?: string;
  quietUninstallString?: string;
  productCode?: string;
  uninstallKeyPath?: string;
}

const SOURCE_ONLY_PUBLISHERS = new Set([
  "pkgutil",
  "homebrew",
  "brew",
  "dpkg",
  "rpm",
  "snap",
  "flatpak",
  "win32-registry",
  "windows-registry",
  "registry",
  "macos-app-bundle"
]);

function cleanString(value?: string | null): string | undefined {
  if (!value) return undefined;

  const cleaned = value
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.length > 0 ? cleaned : undefined;
}

function normalizePublisherForIdentity(publisher?: string | null): string | undefined {
  const p = cleanString(publisher);
  if (!p) return undefined;

  const lower = p.toLowerCase();

  if (SOURCE_ONLY_PUBLISHERS.has(lower)) {
    return undefined;
  }

  return lower;
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

  if (!rawName) {
    return null;
  }

  const version = cleanString(input.version);
  const rawPublisher = cleanString(input.publisher);
  const identityPublisher = normalizePublisherForIdentity(input.publisher);
  const installLocation = cleanString(input.installLocation);
  const packageFamilyName = cleanString(input.packageFamilyName);
  const source = cleanString(input.source)?.toLowerCase() || "unknown";

  /**
   * Technical identity should stay stable and independent from display rules.
   *
   * Example:
   * - rawName/packageFamilyName: com.epson.pkg.EpsonScan2.Utility
   * - displayName: Epson Scan 2 Utility
   *
   * installId must use the technical identity so improving labels later does
   * not produce fake "removed + added" deltas.
   */
  const normalizedIdentityName = rawName.toLowerCase();

  const display = normalizeSoftwareDisplayMetadata({
    name: rawName,
    publisher: rawPublisher,
    source,
    installLocation,
    packageFamilyName
  });

  const detectedAtUtc = new Date().toISOString();

  const installId = generateInstallId({
    name: normalizedIdentityName,
    source,
    packageFamilyName,
    publisher: identityPublisher
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
    category: display.category,

    // ⚠️ SIN `cleanString`. Ese helper existe para nombres que se muestran, y
    // aquí no se muestra nada: un `UninstallString` puede llevar comillas y
    // rutas con espacios que hay que ejecutar EXACTAMENTE como el instalador
    // las registró, y un ProductCode es un GUID que sólo vale entero.
    // `?? undefined` para no plantar `null` en un campo opcional.
    uninstallString: input.uninstallString ?? undefined,
    quietUninstallString: input.quietUninstallString ?? undefined,
    productCode: input.productCode ?? undefined,
    uninstallKeyPath: input.uninstallKeyPath ?? undefined
  };
}