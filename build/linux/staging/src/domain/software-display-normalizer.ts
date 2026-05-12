// src/domain/software-display-normalizer.ts

export type SoftwareDisplayCategory =
  | "application"
  | "driver"
  | "component"
  | "runtime"
  | "system"
  | "package"
  | "unknown";

export interface SoftwareDisplayInput {
  name: string;
  publisher?: string | null;
  source: string;
  packageFamilyName?: string | null;
  installLocation?: string | null;
}

export interface SoftwareDisplayMetadata {
  displayName: string;
  displayPublisher: string;
  userFacing: boolean;
  category: SoftwareDisplayCategory;
}

type VendorRule = {
  pattern: RegExp;
  publisher: string;
};

type NameRule = {
  pattern: RegExp;
  displayName: string;
  displayPublisher?: string;
  category?: SoftwareDisplayCategory;
  userFacing?: boolean;
};

/**
 * These values are collector/source names, not real software publishers.
 *
 * Important:
 * - Never show these values in the dashboard as publisher.
 * - If one of these values arrives as input.publisher, we ignore it and
 *   try to infer the real vendor from packageFamilyName/name.
 */
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

const PRESERVE_UPPERCASE_WORDS = new Set([
  "LLC",
  "LTD",
  "GMBH",
  "SAS",
  "SA",
  "INC",
  "AG",
  "BV",
  "AB",
  "NV",
  "PLC"
]);

const KNOWN_PUBLISHERS: Record<string, string> = {
  "microsoft": "Microsoft",
  "microsoft corporation": "Microsoft",
  "microsoft corp": "Microsoft",
  "microsoft corp.": "Microsoft",

  "google": "Google",
  "google llc": "Google",
  "google inc": "Google",
  "google inc.": "Google",

  "apple": "Apple",
  "apple inc": "Apple",
  "apple inc.": "Apple",

  "epson": "Epson",
  "seiko epson": "Epson",
  "seiko epson corporation": "Epson",

  "teamviewer": "TeamViewer",
  "teamviewer germany gmbh": "TeamViewer",

  "fortinet": "Fortinet",
  "fortinet inc": "Fortinet",
  "fortinet inc.": "Fortinet",

  "citrix": "Citrix",
  "citrix systems": "Citrix",
  "citrix systems inc": "Citrix",
  "citrix systems inc.": "Citrix",

  "crowdstrike": "CrowdStrike",
  "crowdstrike inc": "CrowdStrike",
  "crowdstrike inc.": "CrowdStrike",

  "zoom": "Zoom",
  "zoom video communications": "Zoom",
  "zoom video communications inc": "Zoom",
  "zoom video communications inc.": "Zoom",

  "mozilla": "Mozilla",
  "mozilla corporation": "Mozilla",

  "docker": "Docker",
  "docker inc": "Docker",
  "docker inc.": "Docker",

  "oracle": "Oracle",
  "oracle america inc": "Oracle",
  "oracle america inc.": "Oracle",

  "openai": "OpenAI",
  "anthropic": "Anthropic",
  "nordvpn": "NordVPN",
  "whatsapp": "WhatsApp",
  "nmap": "Nmap",
  "eclipse adoptium": "Eclipse Adoptium",
  "certus": "Certus"
};

const VENDOR_RULES: VendorRule[] = [
  { pattern: /^com\.microsoft\./i, publisher: "Microsoft" },
  { pattern: /^microsoft\b/i, publisher: "Microsoft" },
  { pattern: /\bmicrosoft\b/i, publisher: "Microsoft" },

  { pattern: /^com\.apple\./i, publisher: "Apple" },
  { pattern: /^apple\b/i, publisher: "Apple" },

  { pattern: /^com\.epson\./i, publisher: "Epson" },
  { pattern: /^epson\b/i, publisher: "Epson" },

  { pattern: /^com\.teamviewer\./i, publisher: "TeamViewer" },
  { pattern: /^teamviewer\b/i, publisher: "TeamViewer" },

  { pattern: /^com\.fortinet\./i, publisher: "Fortinet" },
  { pattern: /^fortinet\b/i, publisher: "Fortinet" },

  { pattern: /^com\.citrix\./i, publisher: "Citrix" },
  { pattern: /^citrix\b/i, publisher: "Citrix" },

  { pattern: /^com\.crowdstrike\./i, publisher: "CrowdStrike" },
  { pattern: /^crowdstrike\b/i, publisher: "CrowdStrike" },

  { pattern: /^org\.virtualbox\./i, publisher: "Oracle" },
  { pattern: /^virtualbox\b/i, publisher: "Oracle" },

  { pattern: /^us\.zoom\./i, publisher: "Zoom" },
  { pattern: /^zoom\b/i, publisher: "Zoom" },

  { pattern: /^net\.whatsapp\./i, publisher: "WhatsApp" },
  { pattern: /^desktop\.WhatsApp$/i, publisher: "WhatsApp" },
  { pattern: /^whatsapp\b/i, publisher: "WhatsApp" },

  { pattern: /^com\.google\./i, publisher: "Google" },
  { pattern: /^google\b/i, publisher: "Google" },

  { pattern: /^org\.mozilla\./i, publisher: "Mozilla" },
  { pattern: /^mozilla\b/i, publisher: "Mozilla" },
  { pattern: /^firefox\b/i, publisher: "Mozilla" },

  { pattern: /^com\.docker\./i, publisher: "Docker" },
  { pattern: /^docker\b/i, publisher: "Docker" },

  { pattern: /^com\.openai\./i, publisher: "OpenAI" },
  { pattern: /^openai\b/i, publisher: "OpenAI" },

  { pattern: /^com\.anthropic\./i, publisher: "Anthropic" },
  { pattern: /^anthropic\b/i, publisher: "Anthropic" },

  { pattern: /^com\.nordvpn\./i, publisher: "NordVPN" },
  { pattern: /^nordvpn\b/i, publisher: "NordVPN" },

  { pattern: /^com\.certusws\./i, publisher: "Certus" },

  { pattern: /^net\.temurin\./i, publisher: "Eclipse Adoptium" },
  { pattern: /^temurin\b/i, publisher: "Eclipse Adoptium" },

  { pattern: /^org\.insecure\.nmap/i, publisher: "Nmap" },

  { pattern: /^com\.amazon\./i, publisher: "Amazon" },
  { pattern: /^com\.if\.Amphetamine$/i, publisher: "Amphetamine" },
  { pattern: /^com\.tinyapp\.TablePlus$/i, publisher: "TablePlus" },
  { pattern: /^com\.torusknot\.SourceTreeNotMAS$/i, publisher: "Atlassian" },
  { pattern: /^com\.devolutions\./i, publisher: "Devolutions" },
  { pattern: /^com\.hicknhacksoftware\./i, publisher: "HicknHack Software" },
  { pattern: /^com\.titanium\./i, publisher: "Titanium Software" },
  { pattern: /^com\.caliente\./i, publisher: "Caliente" },
  { pattern: /^com\.google\.android\.studio$/i, publisher: "Google" },
  { pattern: /^net\.metaquotes\./i, publisher: "MetaQuotes" },
  { pattern: /^notion\.id$/i, publisher: "Notion" },
  { pattern: /^com\.carriez\.rustdesk$/i, publisher: "RustDesk" },
  { pattern: /^com\.philandro\.anydesk$/i, publisher: "AnyDesk" }
];

const NAME_RULES: NameRule[] = [
  { pattern: /^com\.microsoft\.package\.Microsoft_Outlook\.app$/i, displayName: "Microsoft Outlook", displayPublisher: "Microsoft" },
  { pattern: /^com\.microsoft\.package\.Microsoft_PowerPoint\.app$/i, displayName: "Microsoft PowerPoint", displayPublisher: "Microsoft" },
  { pattern: /^com\.microsoft\.package\.Microsoft_OneNote\.app$/i, displayName: "Microsoft OneNote", displayPublisher: "Microsoft" },
  { pattern: /^com\.microsoft\.package\.Microsoft_AutoUpdate\.app$/i, displayName: "Microsoft AutoUpdate", displayPublisher: "Microsoft", category: "component", userFacing: false },
  { pattern: /^com\.microsoft\.pkg\.licensing$/i, displayName: "Microsoft Licensing", displayPublisher: "Microsoft", category: "component", userFacing: false },
  { pattern: /^com\.microsoft\.MSTeamsAudioDevice$/i, displayName: "Microsoft Teams Audio Device", displayPublisher: "Microsoft", category: "driver", userFacing: false },
  { pattern: /^com\.microsoft\.OneDrive-mac$/i, displayName: "OneDrive", displayPublisher: "Microsoft" },

  { pattern: /^com\.apple\.pkg\.Keynote\d+$/i, displayName: "Keynote", displayPublisher: "Apple" },
  { pattern: /^com\.apple\.pkg\.Numbers\d+$/i, displayName: "Numbers", displayPublisher: "Apple" },
  { pattern: /^com\.apple\.pkg\.Pages\d+$/i, displayName: "Pages", displayPublisher: "Apple" },
  { pattern: /^com\.apple\.pkg\.Xcode$/i, displayName: "Xcode", displayPublisher: "Apple" },
  { pattern: /^com\.apple\.pkg\.RosettaUpdateAuto$/i, displayName: "Rosetta 2", displayPublisher: "Apple", category: "system", userFacing: false },
  { pattern: /^com\.apple\.pkg\.MobileDeviceDevelopment$/i, displayName: "Apple Mobile Device Development", displayPublisher: "Apple", category: "component", userFacing: false },
  { pattern: /^com\.apple\.files\.data-template$/i, displayName: "Apple Files Data Template", displayPublisher: "Apple", category: "system", userFacing: false },
  { pattern: /^com\.apple\.cdm\.pkg\.Keynote_MASReceipt$/i, displayName: "Keynote Receipt", displayPublisher: "Apple", category: "component", userFacing: false },
  { pattern: /^com\.apple\.cdm\.pkg\.Numbers_MASReceipt$/i, displayName: "Numbers Receipt", displayPublisher: "Apple", category: "component", userFacing: false },
  { pattern: /^com\.apple\.cdm\.pkg\.Pages_MASReceipt$/i, displayName: "Pages Receipt", displayPublisher: "Apple", category: "component", userFacing: false },
  { pattern: /^com\.apple\.cdm\.pkg\.iMovie_MASReceipt$/i, displayName: "iMovie Receipt", displayPublisher: "Apple", category: "component", userFacing: false },

  { pattern: /^com\.epson\.pkg\.EpsonScan2$/i, displayName: "Epson Scan 2", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.EpsonScan2\.Utility$/i, displayName: "Epson Scan 2 Utility", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.pkg\.EpsonScan2\.help$/i, displayName: "Epson Scan 2 Help", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.pkg\.EpsonScan2\.(ica|twain)$/i, displayName: "Epson Scan 2 Driver", displayPublisher: "Epson", category: "driver", userFacing: false },
  { pattern: /^com\.epson\.pkg\.EpsonScan2\.standalone$/i, displayName: "Epson Scan 2 Standalone", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.EPSONSoftwareUpdater$/i, displayName: "Epson Software Updater", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.ScanSmart\.app$/i, displayName: "Epson ScanSmart", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.eventmanager$/i, displayName: "Epson Event Manager", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.easyphotoscan$/i, displayName: "Epson Easy Photo Scan", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.EpsonPhotoPlus$/i, displayName: "Epson Photo+", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.scannermonitor$/i, displayName: "Epson Scanner Monitor", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.pkg\.Ocr(\.SysIntel)?$/i, displayName: "Epson OCR", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.fpkg\.EpsonConnectPrinterSetup$/i, displayName: "Epson Connect Printer Setup", displayPublisher: "Epson" },
  { pattern: /^com\.epson\.pkg\.ijpdrv\./i, displayName: "Epson Inkjet Printer Driver", displayPublisher: "Epson", category: "driver", userFacing: false },
  { pattern: /^com\.epson\.fpkg\.ECPS/i, displayName: "Epson Connect Printer Setup", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.guide\./i, displayName: "Epson User Guide", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.pkg\.AppletW$/i, displayName: "Epson Applet", displayPublisher: "Epson", category: "component", userFacing: false },
  { pattern: /^com\.epson\.pkg\.Epdfcihr\.arm$/i, displayName: "Epson PDF Component", displayPublisher: "Epson", category: "component", userFacing: false },

  { pattern: /^com\.teamviewer\.remoteaudiodriver$/i, displayName: "TeamViewer Remote Audio Driver", displayPublisher: "TeamViewer", category: "driver", userFacing: false },
  { pattern: /^com\.teamviewer\.AuthorizationPlugin$/i, displayName: "TeamViewer Authorization Plugin", displayPublisher: "TeamViewer", category: "component", userFacing: false },
  { pattern: /^com\.teamviewer\.teamviewerUninstallerHelper$/i, displayName: "TeamViewer Uninstaller Helper", displayPublisher: "TeamViewer", category: "component", userFacing: false },
  { pattern: /^com\.teamviewer\.teamviewerPriviledgedHelper$/i, displayName: "TeamViewer Privileged Helper", displayPublisher: "TeamViewer", category: "component", userFacing: false },
  { pattern: /^com\.teamviewer\.teamviewerEnforceUIVersion$/i, displayName: "TeamViewer UI Version Enforcer", displayPublisher: "TeamViewer", category: "component", userFacing: false },

  { pattern: /^com\.fortinet\.forticlient\.FortiClientarm64$/i, displayName: "FortiClient", displayPublisher: "Fortinet" },
  { pattern: /^com\.fortinet\.forticlient\.vpnservice$/i, displayName: "FortiClient VPN Service", displayPublisher: "Fortinet", category: "component", userFacing: false },
  { pattern: /^com\.fortinet\.forticlient\.commservice$/i, displayName: "FortiClient Communication Service", displayPublisher: "Fortinet", category: "component", userFacing: false },
  { pattern: /^com\.fortinet\.forticlient\.fssoagent$/i, displayName: "FortiClient FSSO Agent", displayPublisher: "Fortinet", category: "component", userFacing: false },
  { pattern: /^com\.fortinet\.forticlient\.(preinstall|postinstall)$/i, displayName: "FortiClient Installer Component", displayPublisher: "Fortinet", category: "component", userFacing: false },
  { pattern: /^com\.fortinet\.forticlient\.Uninstall$/i, displayName: "FortiClient Uninstaller", displayPublisher: "Fortinet", category: "component", userFacing: false },

  { pattern: /^com\.citrix\.ICAClient/i, displayName: "Citrix Workspace", displayPublisher: "Citrix" },
  { pattern: /^com\.citrix\.common$/i, displayName: "Citrix Common Components", displayPublisher: "Citrix", category: "component", userFacing: false },

  { pattern: /^com\.crowdstrike\.falcon\.sensor\.sysx$/i, displayName: "CrowdStrike Falcon Sensor", displayPublisher: "CrowdStrike", category: "component", userFacing: false },

  { pattern: /^org\.virtualbox\.pkg\.virtualbox$/i, displayName: "VirtualBox", displayPublisher: "Oracle" },
  { pattern: /^org\.virtualbox\.pkg\.virtualboxcli$/i, displayName: "VirtualBox CLI", displayPublisher: "Oracle", category: "component", userFacing: false },

  { pattern: /^us\.zoom\.pkg\.videomeeting$/i, displayName: "Zoom", displayPublisher: "Zoom" },
  { pattern: /^desktop\.WhatsApp$/i, displayName: "WhatsApp", displayPublisher: "WhatsApp" },

  { pattern: /^org\.insecure\.nmap$/i, displayName: "Nmap", displayPublisher: "Nmap" },
  { pattern: /^org\.insecure\.nmap\.ncat$/i, displayName: "Ncat", displayPublisher: "Nmap", category: "component", userFacing: false },
  { pattern: /^org\.insecure\.nmap\.nping$/i, displayName: "Nping", displayPublisher: "Nmap", category: "component", userFacing: false },
  { pattern: /^org\.insecure\.nmap\.zenmap$/i, displayName: "Zenmap", displayPublisher: "Nmap" },

  { pattern: /^net\.temurin\.(\d+)\.jdk$/i, displayName: "Eclipse Temurin JDK $1", displayPublisher: "Eclipse Adoptium", category: "runtime" },

  { pattern: /^com\.certusws\.tracenium\.agent$/i, displayName: "Tracenium Agent", displayPublisher: "Certus" },
  { pattern: /^com\.certusws\.tracenium\.agentstatus$/i, displayName: "Tracenium Agent Status", displayPublisher: "Certus" }
];

const DRIVER_OR_COMPONENT_HINTS = [
  /driver/i,
  /audio\s*device/i,
  /remote\s*audio/i,
  /authorization\s*plugin/i,
  /privileged\s*helper/i,
  /uninstaller\s*helper/i,
  /scanner\s*monitor/i,
  /communication\s*service/i,
  /vpn\s*service/i,
  /installer\s*component/i,
  /licensing/i,
  /receipt/i,
  /masreceipt/i,
  /software\s*updater/i,
  /update\s*helper/i,
  /common\s*components/i
];

export function normalizeSoftwareDisplayMetadata(input: SoftwareDisplayInput): SoftwareDisplayMetadata {
  const rawName = clean(input.name) || "Unknown Software";
  const technicalName = clean(input.packageFamilyName) || rawName;
  const source = clean(input.source)?.toLowerCase() || "unknown";

  const explicitRule = NAME_RULES.find(rule =>
    rule.pattern.test(technicalName) || rule.pattern.test(rawName)
  );

  const displayName = explicitRule?.displayName
    ? applyRegexDisplayName(explicitRule.pattern, explicitRule.displayName, technicalName)
    : buildDisplayName(rawName, technicalName, source);

  const displayPublisher =
    explicitRule?.displayPublisher ||
    normalizePublisherName(input.publisher, rawName, technicalName, source);

  const category = explicitRule?.category || inferCategory(displayName, technicalName, source);
  const userFacing = explicitRule?.userFacing ?? inferUserFacing(category, source, displayName, technicalName);

  return {
    displayName,
    displayPublisher,
    userFacing,
    category
  };
}

export function normalizePublisherName(
  publisher?: string | null,
  name?: string | null,
  packageFamilyName?: string | null,
  source?: string | null
): string {
  const rawPublisher = clean(publisher);
  const lowerPublisher = rawPublisher?.toLowerCase();

  /**
   * If publisher is real, canonicalize it.
   * If publisher is a technical collector/source name, ignore it.
   *
   * Example:
   *   publisher="microsoft"              -> Microsoft
   *   publisher="Microsoft Corporation"  -> Microsoft
   *   publisher="pkgutil"                -> ignored, infer from packageFamilyName/name
   *   publisher="macos-app-bundle"       -> ignored, infer from packageFamilyName/name
   */
  if (rawPublisher && lowerPublisher && !SOURCE_ONLY_PUBLISHERS.has(lowerPublisher)) {
    return canonicalizeKnownPublisher(rawPublisher);
  }

  const inferredPublisher = inferPublisher(packageFamilyName, name);

  if (inferredPublisher) {
    return inferredPublisher;
  }

  return "Unknown";
}

function clean(value?: string | null): string | undefined {
  if (!value) return undefined;

  const cleaned = value
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.length > 0 ? cleaned : undefined;
}

function canonicalizeKnownPublisher(value: string): string {
  const normalized = value
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[,.]+$/g, "")
    .toLowerCase();

  if (KNOWN_PUBLISHERS[normalized]) {
    return KNOWN_PUBLISHERS[normalized];
  }

  const withoutLegalSuffix = normalized
    .replace(/\b(incorporated|inc\.?|corporation|corp\.?|llc|ltd\.?)\b/gi, "")
    .replace(/\s+/g, " ")
    .replace(/[,.]+$/g, "")
    .trim();

  if (KNOWN_PUBLISHERS[withoutLegalSuffix]) {
    return KNOWN_PUBLISHERS[withoutLegalSuffix];
  }

  return toTitleCase(value);
}

function inferPublisher(...values: Array<string | undefined | null>): string | undefined {
  for (const value of values) {
    if (!value) continue;

    for (const rule of VENDOR_RULES) {
      if (rule.pattern.test(value)) {
        return rule.publisher;
      }
    }
  }

  return undefined;
}

function buildDisplayName(rawName: string, technicalName: string, source: string): string {
  const cleanRawName = clean(rawName) || technicalName;

  /**
   * Good collector sources usually already provide human-readable app names.
   *
   * Examples:
   *   Google Chrome
   *   Microsoft Teams
   *   Visual Studio Code
   */
  if (source === "macos-app-bundle" || source === "win32-registry" || source === "windows-registry") {
    return titleKnownAcronyms(cleanRawName);
  }

  /**
   * If the raw name is not a reverse-DNS/package id, keep it with light cleanup.
   */
  if (!looksTechnical(cleanRawName)) {
    return titleKnownAcronyms(cleanRawName.replace(/[_-]+/g, " "));
  }

  return humanizeTechnicalId(technicalName);
}

function looksTechnical(value: string): boolean {
  return (
    /^(com|org|net|io|us|desktop)\./i.test(value) ||
    /\.pkg\./i.test(value) ||
    /\.package\./i.test(value) ||
    /[_-]/.test(value)
  );
}

function humanizeTechnicalId(value: string): string {
  let result = value
    .replace(/^(com|org|net|io|us)\./i, "")
    .replace(/\.pkg\./gi, ".")
    .replace(/\.package\./gi, ".")
    .replace(/\.app$/gi, "")
    .replace(/\.cdm\.pkg\./gi, ".")
    .replace(/_MASReceipt$/i, "")
    .replace(/[_-]+/g, " ")
    .replace(/\./g, " ")
    .replace(/\b(and|or)\b/gi, match => match.toLowerCase())
    .replace(/\s+/g, " ")
    .trim();

  result = splitCamelCase(result);
  result = toTitleCase(result);
  result = titleKnownAcronyms(result);

  return result || value;
}

function splitCamelCase(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim();
}

function toTitleCase(value: string): string {
  return value
    .trim()
    .replace(/\s+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map(part => {
      if (/^[A-Z0-9]{2,}$/.test(part)) return part;
      if (/^\d+$/.test(part)) return part;

      const lower = part.toLowerCase();
      const upper = lower.toUpperCase();

      if (PRESERVE_UPPERCASE_WORDS.has(upper)) {
        return upper;
      }

      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function titleKnownAcronyms(value: string): string {
  return value
    .replace(/\bJdk\b/g, "JDK")
    .replace(/\bJre\b/g, "JRE")
    .replace(/\bSdk\b/g, "SDK")
    .replace(/\bApi\b/g, "API")
    .replace(/\bVpn\b/g, "VPN")
    .replace(/\bUsb\b/g, "USB")
    .replace(/\bCli\b/g, "CLI")
    .replace(/\bOcr\b/g, "OCR")
    .replace(/\bIca\b/g, "ICA")
    .replace(/\bTwain\b/g, "TWAIN")
    .replace(/\bNcat\b/g, "Ncat")
    .replace(/\bNping\b/g, "Nping")
    .replace(/\bXcode\b/g, "Xcode")
    .replace(/\bMacos\b/g, "macOS")
    .replace(/\bIos\b/g, "iOS")
    .replace(/\bCpu\b/g, "CPU")
    .replace(/\bGpu\b/g, "GPU")
    .replace(/\bUi\b/g, "UI")
    .replace(/\bPdf\b/g, "PDF");
}

function inferCategory(displayName: string, technicalName: string, source: string): SoftwareDisplayCategory {
  const combined = `${displayName} ${technicalName}`;

  if (/^(dpkg|rpm)$/i.test(source)) return "package";
  if (/jdk|jre|runtime|dotnet|node|python|java/i.test(combined)) return "runtime";
  if (/driver|audio\s*device|usbclassdriver/i.test(combined)) return "driver";
  if (DRIVER_OR_COMPONENT_HINTS.some(re => re.test(combined))) return "component";
  if (/rosetta|gatekeeper|xprotect|mobiledevice|data-template/i.test(combined)) return "system";

  /**
   * pkgutil/homebrew/snap/flatpak frequently report packages and components.
   * If they look technical and no explicit NAME_RULE promoted them, mark them
   * as component by default.
   */
  if (/pkgutil|homebrew|snap|flatpak/i.test(source) && looksTechnical(technicalName)) {
    return "component";
  }

  return "application";
}

function inferUserFacing(
  category: SoftwareDisplayCategory,
  source: string,
  displayName: string,
  technicalName: string
): boolean {
  if (category === "driver" || category === "component" || category === "system") return false;
  if (category === "package" && /^(dpkg|rpm)$/i.test(source)) return false;
  if (DRIVER_OR_COMPONENT_HINTS.some(re => re.test(`${displayName} ${technicalName}`))) return false;

  return true;
}

function applyRegexDisplayName(pattern: RegExp, template: string, value: string): string {
  const match = value.match(pattern);

  if (!match) {
    return template;
  }

  return template.replace(/\$(\d+)/g, (_, index: string) => match[Number(index)] || "");
}