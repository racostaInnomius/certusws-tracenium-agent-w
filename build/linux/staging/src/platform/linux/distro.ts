// src/platform/linux/distro.ts
//
// Linux distro family detection. The single binary supports debian-
// family (Debian/Ubuntu/Mint/Pop!_OS/Raspbian) and rhel-family (RHEL/
// CentOS/Rocky/Alma/Fedora/Amazon Linux/Oracle Linux) at MVP; suse-
// family (openSUSE/SLES) lights up in Phase 10. Plugins that branch
// on family (PMP, SDP, PMv2 remediations) call detectFamily() once
// and cache the result on AgentContext — see ctx.platform.linux.
//
// /etc/os-release is the canonical source per the freedesktop.org
// spec; every systemd distro has it. We read it once, cache the
// parsed shape, and never re-read (the host doesn't change distro
// at runtime).
//
// What we DON'T use:
//   * `lsb_release` — the lsb_release binary isn't installed by
//     default on minimal Debian/Rocky/Alma images and shelling out
//     adds a fork+exec to a hot path.
//   * `/etc/redhat-release` etc. — distro-specific files that
//     pre-date /etc/os-release. /etc/os-release covers every distro
//     we support, no need for fallbacks.
//
// What we DO use as a fallback:
//   * ID_LIKE — when ID is a flavour we haven't seen (e.g. ID=neon
//     for KDE Neon), ID_LIKE="ubuntu debian" tells us it's debian-
//     family. This catches downstream rebrands without us having to
//     enumerate them.
import fs from "fs";

export type LinuxFamily = "debian" | "rhel" | "suse" | "unknown";

export type LinuxDistro = {
  id: string;          // raw ID from /etc/os-release, lowercased
  family: LinuxFamily; // resolved family bucket
  versionId: string;   // VERSION_ID, "" if absent (rolling distros like Arch)
  prettyName: string;  // PRETTY_NAME for human-readable logs
};

const FAMILY_BY_ID: Record<string, LinuxFamily> = {
  // debian-family
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

  // rhel-family
  rhel: "rhel",
  centos: "rhel",
  rocky: "rhel",
  almalinux: "rhel",
  fedora: "rhel",
  amzn: "rhel",
  ol: "rhel", // Oracle Linux
  scientific: "rhel",

  // suse-family — shipped as supported in Phase 10. Listed here so
  // detection is correct even before we add SUSE-specific plugin
  // branches; the plugins themselves return `unsupported_distro`
  // until then.
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
    // Strip surrounding quotes (single or double). os-release values
    // are formally shell-syntax, but in practice nobody puts escaped
    // quotes inside, so a simple strip is sufficient.
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
  // ID_LIKE is space-separated, lowercase. First match wins — vendors
  // list closest-to-distant lineage, e.g. ID_LIKE="ubuntu debian" on
  // Pop!_OS.
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
    // No /etc/os-release means we're on a non-systemd distro (or a
    // wildly minimal container). Return unknown; plugins will refuse
    // to do family-specific work and the operator will see it in the
    // first heartbeat's facts.
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

// Test-only: clear the cache so unit tests can mock /etc/os-release
// across cases. Production callers should never hit this path.
export function _resetForTests() {
  cached = null;
}
