// src/bootstrap/token-source.ts
import { execSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";

function enrollmentTokenFilePath(): string | null {
  if (process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE) {
    return process.env.TRACENIUM_ENROLLMENT_TOKEN_FILE;
  }

  if (os.platform() === "darwin") {
    return "/Library/Application Support/Tracenium/Agent/enrollment.token";
  }

  if (os.platform() === "linux") {
    return "/var/lib/tracenium/enrollment.token";
  }

  return null;
}

function readTokenFile(): string | null {
  const file = enrollmentTokenFilePath();
  if (!file) return null;

  try {
    if (!fs.existsSync(file)) return null;
    const token = fs.readFileSync(file, "utf8").trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

export function readEnrollmentToken(): string | null {
  // environment (funciona en dev / testing)
  if (process.env.ENROLLMENT_TOKEN) {
    return process.env.ENROLLMENT_TOKEN;
  }

  const tokenFromFile = readTokenFile();
  if (tokenFromFile) {
    return tokenFromFile;
  }

  // registry (usado en producción)
  if (os.platform() === "win32") {
    try {
      const out = execSync(
        'reg query "HKLM\\Software\\CertusWS\\Tracenium" /v ENROLLMENT_TOKEN',
        { stdio: ["pipe", "pipe", "ignore"] }
      ).toString();

      const parts = out.split("REG_SZ");
      if (parts.length > 1) {
        return parts[1].trim();
      }
    } catch {}
  }

  return null;
}

/**
 * Securely clear the enrollment token file.
 *
 * A plain `rm` just unlinks the directory entry — the original bytes stay
 * on disk until the filesystem reuses them, so a short-lived enrollment
 * token remains recoverable via disk forensics (or just `grep` on a raw
 * block device) long after enrollment completes. This matters because
 * enrollment tokens are bearer credentials: anyone who recovers one can
 * register a rogue device against the tenant until the token is revoked
 * server-side.
 *
 * Strategy: open the file for read+write, overwrite its contents with
 * cryptographic-random bytes of the same length, fsync to force the write
 * through the page cache, THEN unlink. This is a best-effort shred — on
 * copy-on-write filesystems (APFS, btrfs, ZFS) and SSDs with wear
 * leveling the original blocks may still exist. But for the common case
 * (HFS+, ext4, directly-attached SSD with TRIM) it substantially raises
 * the bar for recovery, and it's free: we do it once, at enrollment.
 */
export function clearEnrollmentTokenFile(): void {
  const file = enrollmentTokenFilePath();
  if (!file) return;

  try {
    if (!fs.existsSync(file)) return;

    // Overwrite with random bytes before unlinking. We do two passes:
    // once with random bytes, once with zeros — covers both "forensic
    // pattern detection" and "uninitialized memory read" recovery paths.
    let fd: number | null = null;
    try {
      const stat = fs.statSync(file);
      const size = stat.size;

      if (size > 0) {
        fd = fs.openSync(file, "r+");

        const rand = crypto.randomBytes(size);
        fs.writeSync(fd, rand, 0, size, 0);
        try { fs.fsyncSync(fd); } catch {}

        const zeros = Buffer.alloc(size, 0);
        fs.writeSync(fd, zeros, 0, size, 0);
        try { fs.fsyncSync(fd); } catch {}
      }
    } catch {
      // Fall through to unlink even if the shred failed — a plain
      // unlink is still better than leaving the token on disk.
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch {}
      }
    }

    try {
      fs.rmSync(file, { force: true });
    } catch {}
  } catch {}
}
