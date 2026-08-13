/**
 * Gateway self-verification ladder.
 *
 * PURE orchestration over injected dependencies — no sockets, no XML. Runs on
 * the Infrastructure Gateway because it is the only place that can decrypt the
 * vCenter credential; the control plane never can. The credential is opaque to
 * the backend, but the RESULT of using it is not, so this produces a structured
 * diagnostic that travels back over the existing ACK channel.
 *
 * Rungs are ordered cheapest-and-most-fundamental first, so the report names
 * the exact layer that broke instead of a useless "connection failed".
 *
 * See ADR-0001 section (C-bis).
 */

export type VerifyStage =
  | "reachability"
  | "tls_pin"
  | "authentication"
  | "privileges"
  | "scope";

export type FailureClass =
  | "network"
  | "tls_pin_mismatch"
  | "bad_credentials"
  | "password_expired"
  | "account_locked"
  | "insufficient_privileges"
  | "empty_scope"
  | "unknown";

/** Exactly the privileges the connector needs — nothing more. */
export const REQUIRED_PRIVILEGES = [
  "VirtualMachine.State.CreateSnapshot",
  "VirtualMachine.State.RemoveSnapshot",
  "VirtualMachine.State.RevertToSnapshot",
] as const;

export interface PrivilegeCheck {
  priv: string;
  /** Server advertises this privilege id (present in privilegeList). */
  supported: boolean;
  /** Session holds it. Meaningless when `supported` is false. */
  granted: boolean;
}

export interface VerifyStageResult {
  stage: VerifyStage;
  ok: boolean;
  detail?: string;
  error?: string;
  classify?: FailureClass;
  remediation?: string;
  privileges?: PrivilegeCheck[];
  /** Non-fatal note, e.g. no thumbprint pinned. */
  warn?: boolean;
}

export interface VerifyReport {
  ok: boolean;
  stages: VerifyStageResult[];
  failedStage: VerifyStage | null;
  classify: FailureClass | null;
  /**
   * Whether an automatic retry is safe. FALSE for every credential-related
   * failure: vSphere locks accounts after N bad attempts, so auto-retrying a
   * typo would escalate it into a locked service account.
   */
  retryable: boolean;
  remediation: string | null;
  verifiedAtUtc: string;
}

export interface VerifyConfig {
  host: string;
  port: number;
  /** SHA-256 of the vCenter cert, any separator/case. Empty = no pinning. */
  tlsThumbprintSha256?: string;
  /** Entity the privilege check is evaluated against (root folder by default). */
  entityMoref?: string;
  entityType?: string;
}

export interface VerifyDeps {
  /** TCP+TLS handshake; resolves with elapsed ms. */
  probeReachability(host: string, port: number): Promise<number>;
  /** Server certificate SHA-256, hex, no separators. */
  serverFingerprint(host: string, port: number): Promise<string>;
  /** SOAP Login. Rejects with the vCenter fault message on failure. */
  login(): Promise<{ sessionKey: string; userName: string }>;
  /** AuthorizationManager.privilegeList — everything this build knows about. */
  listPrivileges(): Promise<string[]>;
  /** HasPrivilegeOnEntity; booleans in the same order as `privIds`. */
  checkPrivileges(sessionKey: string, privIds: string[], entity: { moref: string; type: string }): Promise<boolean[]>;
  /** Number of VMs visible within the configured scope. */
  countVmsInScope(): Promise<number>;
  logout(): Promise<void>;
  /** Injected clock so reports are deterministic under test. */
  now(): Date;
}

/** Canonical thumbprint form: strip separators, lowercase. Both sides. */
export function normalizeThumbprint(t: unknown): string {
  return typeof t === "string" ? t.replace(/[:\s-]/g, "").toLowerCase() : "";
}

/**
 * Map a vCenter login fault onto a failure class. Conservative by design:
 * anything unrecognised is `unknown`, which is treated as NON-retryable so an
 * unfamiliar auth error can never turn into a lockout loop.
 */
export function classifyLoginError(message: string): FailureClass {
  const m = String(message || "").toLowerCase();
  if (/locked|lockout/.test(m)) return "account_locked";
  if (/expired/.test(m)) return "password_expired";
  if (/incorrect user name or password|invalidlogin|cannot complete login|authentication fail/.test(m)) {
    return "bad_credentials";
  }
  if (/timeout|econnrefused|ehostunreach|enotfound|socket hang up|network/.test(m)) return "network";
  return "unknown";
}

/** Only genuine transport problems may be retried automatically. */
export function isRetryable(c: FailureClass | null): boolean {
  return c === "network";
}

const REMEDIATION: Record<FailureClass, string> = {
  network:
    "The gateway cannot reach vCenter. Check network path, DNS and firewall from the gateway host.",
  tls_pin_mismatch:
    "vCenter presented a different certificate than the pinned one. Verify the certificate changed legitimately, then re-register the thumbprint.",
  bad_credentials:
    "vCenter rejected the credentials. Re-enter the service account username and password. Do NOT retry automatically — vSphere locks the account after repeated failures.",
  password_expired:
    "The service account password has expired. Renew it in vSphere, then re-provision the credential.",
  account_locked:
    "The service account is locked in vSphere. Unlock it and wait out the lockout window before retrying.",
  insufficient_privileges:
    "Grant the service account a role holding the missing snapshot privileges on the target folder or datacenter, with propagation enabled.",
  empty_scope:
    "The service account cannot see any VM in the configured scope. Check folder selection and that permissions propagate to child objects.",
  unknown: "Unexpected vCenter error. See the stage detail and the gateway log.",
};

function fail(
  stage: VerifyStage,
  error: string,
  classify: FailureClass,
  extra: Partial<VerifyStageResult> = {}
): VerifyStageResult {
  return { stage, ok: false, error, classify, remediation: REMEDIATION[classify], ...extra };
}

/**
 * Run the ladder, stopping at the first failure. Always returns a report — it
 * does not throw, because the report IS the product: the control plane needs to
 * know precisely which rung broke.
 */
export async function runVerification(deps: VerifyDeps, cfg: VerifyConfig): Promise<VerifyReport> {
  const stages: VerifyStageResult[] = [];
  const finish = (): VerifyReport => {
    const bad = stages.find((s) => !s.ok);
    const classify = (bad?.classify as FailureClass) ?? null;
    return {
      ok: !bad,
      stages,
      failedStage: (bad?.stage as VerifyStage) ?? null,
      classify,
      retryable: isRetryable(classify),
      remediation: bad?.remediation ?? null,
      verifiedAtUtc: deps.now().toISOString(),
    };
  };

  // 1 — reachability
  try {
    const ms = await deps.probeReachability(cfg.host, cfg.port);
    stages.push({ stage: "reachability", ok: true, detail: `TCP+TLS handshake in ${ms} ms` });
  } catch (e: any) {
    stages.push(fail("reachability", String(e?.message ?? e), "network"));
    return finish();
  }

  // 2 — TLS pinning. The lab cert is self-signed by the VMCA, so system-CA
  //     validation can never apply; the pin is the only trust anchor.
  try {
    const observed = normalizeThumbprint(await deps.serverFingerprint(cfg.host, cfg.port));
    const pinned = normalizeThumbprint(cfg.tlsThumbprintSha256);
    if (!pinned) {
      stages.push({
        stage: "tls_pin",
        ok: true,
        warn: true,
        detail: `no thumbprint pinned; server presented ${observed.slice(0, 16)}…`,
      });
    } else if (observed !== pinned) {
      stages.push(
        fail(
          "tls_pin",
          `pinned ${pinned.slice(0, 16)}… but server presented ${observed.slice(0, 16)}…`,
          "tls_pin_mismatch"
        )
      );
      return finish();
    } else {
      stages.push({ stage: "tls_pin", ok: true, detail: "server certificate matches pinned thumbprint" });
    }
  } catch (e: any) {
    stages.push(fail("tls_pin", String(e?.message ?? e), "network"));
    return finish();
  }

  // 3 — authentication
  let sessionKey: string;
  try {
    const s = await deps.login();
    sessionKey = s.sessionKey;
    stages.push({ stage: "authentication", ok: true, detail: `authenticated as ${s.userName}` });
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    stages.push(fail("authentication", msg, classifyLoginError(msg)));
    return finish();
  }

  try {
    // 4 — privileges, non-destructively.
    //     Unknown privilege ids make vCenter throw "Authorize Exception" and
    //     poison the whole batch, which would report "no privileges" for a
    //     perfectly good credential. So ask the server what it supports first
    //     and only query ids it recognises.
    try {
      const supported = new Set(await deps.listPrivileges());
      const askable = REQUIRED_PRIVILEGES.filter((p) => supported.has(p));
      const entity = { moref: cfg.entityMoref ?? "group-d1", type: cfg.entityType ?? "Folder" };
      const granted = askable.length
        ? await deps.checkPrivileges(sessionKey, askable, entity)
        : [];

      const checks: PrivilegeCheck[] = REQUIRED_PRIVILEGES.map((priv) => {
        const idx = askable.indexOf(priv);
        return {
          priv,
          supported: idx >= 0,
          granted: idx >= 0 ? granted[idx] === true : false,
        };
      });

      const missing = checks.filter((c) => c.supported && !c.granted).map((c) => c.priv);
      const unsupported = checks.filter((c) => !c.supported).map((c) => c.priv);

      if (missing.length) {
        stages.push(
          fail("privileges", `missing privilege(s): ${missing.join(", ")}`, "insufficient_privileges", {
            privileges: checks,
          })
        );
        return finish();
      }
      stages.push({
        stage: "privileges",
        ok: true,
        warn: unsupported.length > 0,
        detail: unsupported.length
          ? `granted; ${unsupported.length} privilege id(s) not advertised by this vCenter build: ${unsupported.join(", ")}`
          : `all ${checks.length} required privileges granted`,
        privileges: checks,
      });
    } catch (e: any) {
      stages.push(fail("privileges", String(e?.message ?? e), "unknown"));
      return finish();
    }

    // 5 — scope
    try {
      const n = await deps.countVmsInScope();
      if (n === 0) {
        stages.push(fail("scope", "configured scope resolves to 0 VMs", "empty_scope"));
        return finish();
      }
      stages.push({ stage: "scope", ok: true, detail: `${n} VM(s) visible in scope` });
    } catch (e: any) {
      stages.push(fail("scope", String(e?.message ?? e), "unknown"));
      return finish();
    }

    return finish();
  } finally {
    // Never leave a vCenter session dangling, whatever happened above.
    await deps.logout().catch(() => {});
  }
}
