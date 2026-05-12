// privsvc/linux/src/distro.ts
//
// Family detection for the privsvc bundle. Mirrors src/platform/
// linux/distro.ts on the agent side — duplicated rather than shared
// because the privsvc tsconfig has its own rootDir, and we want both
// bundles to be standalone (no path-mapping config across them).
//
// The duplication is small and the data is static: if a new distro
// shows up that we want to recognize, both files need updating, but
// "we forgot to update one half" is caught by the family-specific
// branches in either consumer falling back to "unknown" → catalog
// not_applicable, which is loud rather than silent.
import fs from "fs";

export type LinuxFamily = "debian" | "rhel" | "suse" | "unknown";

export type LinuxDistro = {
  id: string;
  family: LinuxFamily;
  versionId: string;
  prettyName: string;
};

const FAMILY_BY_ID: Record<string, LinuxFamily> = {
  debian: "debian",
  ubuntu: "debian",
  raspbian: "debian",
  linuxmint: "debian",
  pop: "debian",
  neon: "debian",
  elementary: "debian",
  zorin: "debian",
  kali: "debian",
  parrot: "debian",

  rhel: "rhel",
  centos: "rhel",
  rocky: "rhel",
  almalinux: "rhel",
  fedora: "rhel",
  amzn: "rhel",
  ol: "rhel",
  scientific: "rhel",

  opensuse: "suse",
  "opensuse-leap": "suse",
  "opensuse-tumbleweed": "suse",
  sles: "suse",
  sled: "suse",
};

let cached: LinuxDistro | null = null;

function parseOsRelease(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function familyFromIdLike(idLike: string | undefined): LinuxFamily {
  if (!idLike) return "unknown";
  for (const token of idLike.toLowerCase().split(/\s+/)) {
    const fam = FAMILY_BY_ID[token];
    if (fam) return fam;
  }
  return "unknown";
}

export function detectFamily(): LinuxDistro {
  if (cached) return cached;

  let kv: Record<string, string> = {};
  try {
    const text = fs.readFileSync("/etc/os-release", "utf8");
    kv = parseOsRelease(text);
  } catch {
    // No /etc/os-release: non-systemd or wildly minimal container.
    // Fall through with the unknown defaults below.
  }

  const id = (kv.ID || "unknown").toLowerCase();
  const family = FAMILY_BY_ID[id] ?? familyFromIdLike(kv.ID_LIKE);

  cached = {
    id,
    family,
    versionId: kv.VERSION_ID || "",
    prettyName: kv.PRETTY_NAME || (id !== "unknown" ? id : "unknown linux"),
  };
  return cached;
}
