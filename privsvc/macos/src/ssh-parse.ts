// privsvc/macos/src/ssh-parse.ts
//
// Pure parser for `sshd -T` effective-config output on macOS. Produces the SAME
// evidence shape as the Linux ssh collector so the SAME catalog rules
// (ssh.ciphers / ssh.macs / ssh.kexAlgorithms weak-algorithm checks, etc.)
// evaluate on macOS — this is the "crypto" parity with Linux that replaces the
// old macOS `crypto` stub (macOS has no SCHANNEL-style registry; its crypto
// posture, like Linux's, lives in the SSH algorithm lists).
//
// Dependency-free + pure so it's unit-testable without a running sshd.

const RAW_MAX = 4 * 1024;

export interface SshEvidence {
  enabled: boolean | "unknown";
  permitRootLogin?: string;
  passwordAuthentication?: boolean;
  pubkeyAuthentication?: boolean;
  challengeResponseAuthentication?: boolean;
  permitEmptyPasswords?: boolean;
  protocol?: string;
  kexAlgorithms?: string[];
  ciphers?: string[];
  macs?: string[];
  hostKeyAlgorithms?: string[];
  loginGraceTime?: number;
  maxAuthTries?: number;
  x11Forwarding?: boolean;
  raw?: string;
}

/**
 * Parse `sshd -T` output (space-separated `key value` lines) into ssh evidence.
 * Empty/failed output → { enabled: "unknown" }. Mirrors the Linux collector's
 * field extraction exactly so both platforms share catalog rule paths.
 */
export function parseSshdConfig(output: string): SshEvidence {
  const text = output || "";
  if (!text.trim()) return { enabled: "unknown" };

  const map: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    if (space <= 0) continue;
    const key = trimmed.slice(0, space).toLowerCase();
    map[key] = trimmed.slice(space + 1).trim();
  }

  // sshd -T always emits its core directives; if none are present the output
  // was noise/an error, so report unknown rather than a hollow "enabled".
  if (map["ciphers"] === undefined && map["permitrootlogin"] === undefined) {
    return { enabled: "unknown", raw: text.slice(0, RAW_MAX) };
  }

  const yn = (k: string): boolean | undefined => {
    const v = map[k];
    if (v === "yes") return true;
    if (v === "no") return false;
    return undefined;
  };
  const csv = (k: string): string[] | undefined => {
    const v = map[k];
    if (!v) return undefined;
    return v.split(",").map((s) => s.trim()).filter(Boolean);
  };

  return {
    enabled: true,
    permitRootLogin: map["permitrootlogin"],
    passwordAuthentication: yn("passwordauthentication"),
    pubkeyAuthentication: yn("pubkeyauthentication"),
    challengeResponseAuthentication: yn("challengeresponseauthentication") ?? yn("kbdinteractiveauthentication"),
    permitEmptyPasswords: yn("permitemptypasswords"),
    protocol: map["protocol"],
    kexAlgorithms: csv("kexalgorithms"),
    ciphers: csv("ciphers"),
    macs: csv("macs"),
    hostKeyAlgorithms: csv("hostkeyalgorithms"),
    loginGraceTime: map["logingracetime"] ? Number(map["logingracetime"]) : undefined,
    maxAuthTries: map["maxauthtries"] ? Number(map["maxauthtries"]) : undefined,
    x11Forwarding: yn("x11forwarding"),
    raw: text.slice(0, RAW_MAX),
  };
}
