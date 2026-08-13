import { describe, it, expect, vi } from "vitest";
import {
  runVcenterVerify,
  runVcenterSnapshot,
  classifySnapshotError,
  type ConnectorDeps,
} from "../../src/connectors/vcenter";
import { decodeReport, ACK_OK, ACK_RETRY, ACK_REJECTED, buildVerifyAck, buildSnapshotAck } from "../../src/connectors/vcenter/ack";
import { PinMismatchError, VimFault } from "../../src/connectors/vcenter/vim-client";
import type { GatewayConfig } from "../../src/connectors/vcenter/gateway-config";
import type { VerifyReport } from "../../src/connectors/vcenter/verify";

const FP = "62a20ae2d752fc78934a1134f3b4ecc31914899a6b9cd8ce72279808e15c337d";

const CFG: GatewayConfig = {
  vcenter: { url: "https://10.130.130.3", host: "10.130.130.3", port: 443, tlsThumbprintSha256: FP, credentialRef: "vcenter/default" },
  scope: { folders: [] },
  snapshot: { memory: false, quiesce: true, retentionHours: 24, maxConcurrent: 5, perVmTimeoutSec: 900 },
};

// Real lab facts (ADR-0001 Inc 0): MSIG-VEEAM-SRV.
const TARGET = {
  uuid: "dd4f3942-f393-1a50-8614-c6fa55f75468",
  serial: "VMware-42 39 4f dd 93 f3 50 1a-86 14 c6 fa 55 f7 54 68",
  virtual: true,
};
const VCENTER_UUID = "42394fdd-93f3-501a-8614-c6fa55f75468";

function fakeClient(over: Partial<Record<string, any>> = {}) {
  return {
    fetchServerFingerprint: vi.fn(async () => FP),
    assertPinnedCertificate: vi.fn(async () => {}),
    retrieveServiceContent: vi.fn(async () => ({ rootFolder: "group-d1" })),
    login: vi.fn(async () => ({ sessionKey: "s1", userName: "svc" })),
    listPrivileges: vi.fn(async () => [
      "VirtualMachine.State.CreateSnapshot",
      "VirtualMachine.State.RemoveSnapshot",
      "VirtualMachine.State.RevertToSnapshot",
    ]),
    hasPrivilegeOnEntity: vi.fn(async (_s: string, ids: string[]) => ids.map(() => true)),
    countVms: vi.fn(async () => 19),
    findVmByUuid: vi.fn(async (uuid: string) => (uuid === VCENTER_UUID ? "vm-9637" : null)),
    createSnapshot: vi.fn(async () => "task-1"),
    removeSnapshot: vi.fn(async () => "task-r"),
    revertToSnapshot: vi.fn(async () => "task-v"),
    waitForTask: vi.fn(async () => {}),
    currentSnapshot: vi.fn(async () => "snapshot-13889"),
    logout: vi.fn(async () => {}),
    ...over,
  } as any;
}

function deps(over: Partial<ConnectorDeps> = {}, client = fakeClient()): ConnectorDeps & { client: any } {
  return {
    gatewayConfig: () => CFG,
    getCredential: async () => ({ username: "svc@vsphere.local", password: "s3cret" }),
    makeClient: () => client,
    now: () => new Date("2026-07-08T12:00:00.000Z"),
    client,
    ...over,
  } as any;
}

describe("enablement — config presence is the gate", () => {
  it("rejects verify on a device that is not a gateway", async () => {
    const r = await runVcenterVerify(deps({ gatewayConfig: () => null }));
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("not_a_gateway");
  });

  it("rejects snapshot on a device that is not a gateway", async () => {
    const r = await runVcenterSnapshot(deps({ gatewayConfig: () => null }), { deploymentId: 7, target: TARGET });
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("not_a_gateway");
  });

  it("never touches vCenter when not a gateway", async () => {
    const client = fakeClient();
    await runVcenterSnapshot(deps({ gatewayConfig: () => null }, client), { target: TARGET });
    expect(client.login).not.toHaveBeenCalled();
    expect(client.createSnapshot).not.toHaveBeenCalled();
  });
});

describe("runVcenterVerify", () => {
  it("acks OK with a decodable report on the happy path", async () => {
    const r = await runVcenterVerify(deps());
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toMatch(/^vcenter_verify:ok;/);
    const report = decodeReport<VerifyReport>(r.message)!;
    expect(report.ok).toBe(true);
    expect(report.stages.map((s) => s.stage)).toContain("privileges");
  });

  it("acks REJECTED (not retry) for bad credentials — lockout guard", async () => {
    const client = fakeClient({
      login: vi.fn(async () => { throw new Error("Cannot complete login due to an incorrect user name or password."); }),
    });
    const r = await runVcenterVerify(deps({}, client));
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("classify=bad_credentials");
    const report = decodeReport<VerifyReport>(r.message)!;
    expect(report.retryable).toBe(false);
  });

  it("acks RETRY only for a transport failure", async () => {
    const client = fakeClient({ fetchServerFingerprint: vi.fn(async () => { throw new Error("ETIMEDOUT"); }) });
    const r = await runVcenterVerify(deps({}, client));
    expect(r.status).toBe(ACK_RETRY);
    expect(r.message).toContain("classify=network");
  });

  it("reports a missing credential without contacting vCenter", async () => {
    const client = fakeClient();
    const r = await runVcenterVerify(
      deps({ getCredential: async () => { throw Object.assign(new Error("nothing stored"), { code: "not_found" }); } }, client)
    );
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("classify=no_credential");
    expect(client.login).not.toHaveBeenCalled();
  });

  it("distinguishes a stale envelope from a missing credential", async () => {
    const r = await runVcenterVerify(
      deps({ getCredential: async () => { throw Object.assign(new Error("rotated"), { code: "stale_envelope" }); } })
    );
    expect(r.message).toContain("classify=stale_envelope");
  });

  it("does not leak the password into the ack", async () => {
    const r = await runVcenterVerify(deps());
    expect(r.message).not.toContain("s3cret");
  });
});

describe("runVcenterSnapshot — correlation is fail-closed", () => {
  it("snapshots the VM matched by the byte-swapped uuid", async () => {
    const client = fakeClient();
    const r = await runVcenterSnapshot(deps({}, client), { deploymentId: 42, target: TARGET });
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("vcenter_snapshot:created");
    expect(r.message).toContain("moref=vm-9637");
    expect(r.message).toContain("matchedBy=uuid_swapped");
    expect(r.message).toContain("snapshotId=snapshot-13889");
    expect(client.createSnapshot).toHaveBeenCalledWith("vm-9637", "tracenium-prepatch-42", expect.any(String), false, true);
  });

  it("tries the raw uuid before the swapped one", async () => {
    const client = fakeClient();
    await runVcenterSnapshot(deps({}, client), { deploymentId: 1, target: TARGET });
    expect(client.findVmByUuid.mock.calls[0][0]).toBe(TARGET.uuid);
    expect(client.findVmByUuid.mock.calls[1][0]).toBe(VCENTER_UUID);
  });

  it("takes NO snapshot when nothing correlates", async () => {
    const client = fakeClient({ findVmByUuid: vi.fn(async () => null) });
    const r = await runVcenterSnapshot(deps({}, client), { deploymentId: 5, target: TARGET });
    expect(r.message).toContain("vcenter_snapshot:not_correlated");
    expect(r.status).toBe(ACK_REJECTED);
    expect(client.createSnapshot).not.toHaveBeenCalled();
  });

  it("refuses a physical endpoint outright", async () => {
    const client = fakeClient();
    const r = await runVcenterSnapshot(deps({}, client), {
      deploymentId: 5,
      target: { uuid: TARGET.uuid, virtual: false },
    });
    expect(r.message).toContain("not_correlated");
    expect(client.login).not.toHaveBeenCalled();
  });

  it("aborts before login when the certificate pin fails", async () => {
    const client = fakeClient({
      assertPinnedCertificate: vi.fn(async () => { throw new PinMismatchError("a", "b"); }),
    });
    const r = await runVcenterSnapshot(deps({}, client), { deploymentId: 3, target: TARGET });
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("reason=tls_pin_mismatch");
    expect(client.login).not.toHaveBeenCalled();
  });

  it("honours the configured snapshot flags", async () => {
    const memoryCfg: GatewayConfig = { ...CFG, snapshot: { ...CFG.snapshot, memory: true, quiesce: false } };
    const client = fakeClient();
    await runVcenterSnapshot(deps({ gatewayConfig: () => memoryCfg }, client), { deploymentId: 9, target: TARGET });
    expect(client.createSnapshot).toHaveBeenCalledWith(expect.any(String), expect.any(String), expect.any(String), true, false);
  });

  it("passes the per-VM timeout to the task wait", async () => {
    const client = fakeClient();
    await runVcenterSnapshot(deps({}, client), { deploymentId: 9, target: TARGET });
    expect(client.waitForTask).toHaveBeenCalledWith("task-1", { timeoutMs: 900_000 });
  });

  it("always logs out, even after a failure", async () => {
    const client = fakeClient({ createSnapshot: vi.fn(async () => { throw new VimFault("datastore full"); }) });
    await runVcenterSnapshot(deps({}, client), { deploymentId: 9, target: TARGET });
    expect(client.logout).toHaveBeenCalled();
  });

  it("does not leak the password into the ack", async () => {
    const client = fakeClient({ createSnapshot: vi.fn(async () => { throw new Error("boom s3cret"); }) });
    const r = await runVcenterSnapshot(deps({}, client), { deploymentId: 9, target: TARGET });
    expect(r.message).not.toContain("s3cret");
  });
});

describe("classifySnapshotError — retry only what a retry can fix", () => {
  it("never retries credential or privilege failures", () => {
    for (const msg of [
      "Cannot complete login due to an incorrect user name or password.",
      "Permission to perform this operation was denied.",
    ]) {
      expect(classifySnapshotError(new Error(msg)).retryable).toBe(false);
    }
    expect(classifySnapshotError(new PinMismatchError("a", "b")).retryable).toBe(false);
  });

  it("retries transport and vCenter-side operational faults", () => {
    expect(classifySnapshotError(new Error("ECONNREFUSED")).retryable).toBe(true);
    expect(classifySnapshotError(new VimFault("Insufficient disk space")).retryable).toBe(true);
    expect(classifySnapshotError(new Error("task timed out")).outcome).toBe("timed_out");
  });

  it("treats an unrecognised error as terminal", () => {
    expect(classifySnapshotError(new Error("???")).retryable).toBe(false);
  });
});

describe("ack encoding", () => {
  it("falls back to a compact report when the full one is too large", () => {
    const huge: VerifyReport = {
      ok: false,
      stages: Array.from({ length: 500 }, (_, i) => ({
        stage: "privileges" as const,
        ok: false,
        error: "x".repeat(200),
        detail: `${i}`,
      })),
      failedStage: "privileges",
      classify: "insufficient_privileges",
      retryable: false,
      remediation: "grant it",
      verifiedAtUtc: "2026-07-08T12:00:00.000Z",
    };
    const ack = buildVerifyAck(huge);
    const decoded = decodeReport<any>(ack.message)!;
    // Must still be valid base64url JSON — never a truncated blob.
    expect(decoded.truncated).toBe(true);
    expect(decoded.failedStage).toBe("privileges");
  });

  it("strips separators that would corrupt the k=v framing", () => {
    const ack = buildSnapshotAck({ outcome: "failed", reason: "weird;reason=injected" });
    expect(ack.message.match(/reason=/g)).toHaveLength(1);
  });

  it("returns null when a message carries no report", () => {
    expect(decodeReport("vcenter_snapshot:created;moref=vm-1")).toBeNull();
  });
});

// ── credential provisioning ────────────────────────────────────────────────
import { runVcenterCredentialProvision } from "../../src/connectors/vcenter";
import { buildProvisionAck } from "../../src/connectors/vcenter/ack";

const ENVELOPE = {
  v: 1,
  alg: "RSA-OAEP-256+A256GCM",
  certFingerprint: "aa".repeat(32),
  // Distinctive values: a single-char fixture would trivially appear inside the
  // base64 report and make the "no leak" assertion meaningless.
  ek: "EK-ZZQQ9-sealed-key-material",
  iv: "IV-ZZQQ9-nonce",
  ct: "CT-ZZQQ9-ciphertext-body",
  tag: "TAG-ZZQQ9-auth",
};

const coded = (code: string) => Object.assign(new Error(code), { code });

describe("runVcenterCredentialProvision", () => {
  it("stores the credential and immediately verifies it", async () => {
    const provisionCredential = vi.fn(async () => {});
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential } as any),
      { ref: "vcenter/default", envelope: ENVELOPE }
    );
    expect(provisionCredential).toHaveBeenCalledWith("vcenter/default", ENVELOPE);
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toMatch(/^vcenter_credential_provision:stored/);
    // The admin gets a real answer, not an optimistic "saved".
    expect(r.message).toContain("verified=true");
    expect(decodeReport(r.message)).toMatchObject({ ok: true });
  });

  it("reports 'stored' but surfaces a failing verification", async () => {
    const client = fakeClient({
      login: vi.fn(async () => { throw new Error("Cannot complete login due to an incorrect user name or password."); }),
    });
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => {}) } as any, client),
      { envelope: ENVELOPE }
    );
    expect(r.status).toBe(ACK_OK); // the credential DID store
    expect(r.message).toContain("verified=false");
    expect(r.message).toContain("classify=bad_credentials");
  });

  it("defaults the credential ref", async () => {
    const provisionCredential = vi.fn(async () => {});
    await runVcenterCredentialProvision(deps({ provisionCredential } as any), { envelope: ENVELOPE });
    expect(provisionCredential).toHaveBeenCalledWith("vcenter/default", ENVELOPE);
  });

  it("rejects a missing or non-object envelope without calling PrivSvc", async () => {
    const provisionCredential = vi.fn(async () => {});
    for (const envelope of [undefined, null, "nope", 42]) {
      const r = await runVcenterCredentialProvision(
        deps({ provisionCredential } as any),
        { envelope } as any
      );
      expect(r.status).toBe(ACK_REJECTED);
      expect(r.message).toContain("malformed");
    }
    expect(provisionCredential).not.toHaveBeenCalled();
  });

  it("maps a stale envelope to a terminal, actionable outcome", async () => {
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => { throw coded("stale_envelope"); }) } as any),
      { envelope: ENVELOPE }
    );
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("vcenter_credential_provision:stale_envelope");
    expect(r.message).toMatch(/re-enter/i);
  });

  it("only retries when the OS store is unavailable", async () => {
    const retryable = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => { throw coded("store_unavailable"); }) } as any),
      { envelope: ENVELOPE }
    );
    expect(retryable.status).toBe(ACK_RETRY);

    for (const code of ["decrypt_failed", "malformed", "unsupported_version"]) {
      const r = await runVcenterCredentialProvision(
        deps({ provisionCredential: vi.fn(async () => { throw coded(code); }) } as any),
        { envelope: ENVELOPE }
      );
      // Retrying cannot change a property of the envelope itself.
      expect(r.status).toBe(ACK_REJECTED);
      expect(r.message).toContain(code);
    }
  });

  it("treats an unknown PrivSvc error as terminal", async () => {
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => { throw new Error("???"); }) } as any),
      { envelope: ENVELOPE }
    );
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("rejected");
  });

  it("reports store_unavailable when the agent build has no PrivSvc primitive", async () => {
    const d = deps();
    delete (d as any).provisionCredential;
    const r = await runVcenterCredentialProvision(d, { envelope: ENVELOPE });
    expect(r.status).toBe(ACK_RETRY);
    expect(r.message).toContain("store_unavailable");
  });

  it("still reports success when the credential stored but verification throws", async () => {
    // A verification hiccup must not be reported as a storage failure the admin
    // would "fix" by re-entering a perfectly good password.
    const client = fakeClient({ fetchServerFingerprint: vi.fn(async () => { throw new Error("boom"); }) });
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => {}) } as any, client),
      { envelope: ENVELOPE }
    );
    expect(r.message).toMatch(/^vcenter_credential_provision:stored/);
  });

  it("never leaks the envelope ciphertext into the ack", async () => {
    const r = await runVcenterCredentialProvision(
      deps({ provisionCredential: vi.fn(async () => {}) } as any),
      { envelope: ENVELOPE }
    );
    expect(r.message).not.toContain(ENVELOPE.ek);
    expect(r.message).not.toContain(ENVELOPE.ct);
  });
});

describe("buildProvisionAck", () => {
  it("marks only store_unavailable retryable", () => {
    expect(buildProvisionAck("stored").status).toBe(ACK_OK);
    expect(buildProvisionAck("store_unavailable").status).toBe(ACK_RETRY);
    for (const o of ["stale_envelope", "decrypt_failed", "malformed", "unsupported_version", "rejected"] as const) {
      expect(buildProvisionAck(o).status).toBe(ACK_REJECTED);
    }
  });
});

import { runVcenterCredentialRemove } from "../../src/connectors/vcenter";

describe("runVcenterCredentialRemove", () => {
  it("removes the stored credential", async () => {
    const removeCredential = vi.fn(async () => {});
    const r = await runVcenterCredentialRemove(deps({ removeCredential } as any), { ref: "vcenter/site-b" });
    expect(removeCredential).toHaveBeenCalledWith("vcenter/site-b");
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("removed");
  });

  it("treats an already-absent credential as success", async () => {
    // Idempotent by contract: a repeat delivery, or a host that already forgot,
    // is the desired end state — not an error to retry forever.
    const r = await runVcenterCredentialRemove(
      deps({ removeCredential: vi.fn(async () => { throw Object.assign(new Error("gone"), { code: "not_found" }); } ) } as any),
      {}
    );
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("not_found");
  });

  it("retries when the store is temporarily unavailable", async () => {
    const r = await runVcenterCredentialRemove(
      deps({ removeCredential: vi.fn(async () => { throw Object.assign(new Error("locked"), { code: "store_unavailable" }); } ) } as any),
      {}
    );
    expect(r.status).toBe(ACK_RETRY);
  });

  it("no-ops cleanly on a build without the PrivSvc primitive", async () => {
    const d = deps();
    delete (d as any).removeCredential;
    const r = await runVcenterCredentialRemove(d, {});
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("unsupported");
  });

  it("defaults the ref", async () => {
    const removeCredential = vi.fn(async () => {});
    await runVcenterCredentialRemove(deps({ removeCredential } as any), {});
    expect(removeCredential).toHaveBeenCalledWith("vcenter/default");
  });
});

import { runVcenterSnapshotRemove, runVcenterSnapshotRevert } from "../../src/connectors/vcenter";

const SNAPS = [
  { snapshotResultId: 1, deploymentId: 10, targetDeviceId: "d1", snapshotMoref: "snapshot-1" },
  { snapshotResultId: 2, deploymentId: 10, targetDeviceId: "d2", snapshotMoref: "snapshot-2" },
];

describe("runVcenterSnapshotRemove — one failure must not strand the batch", () => {
  it("removes every snapshot and reports the ids", async () => {
    const client = fakeClient({ removeSnapshot: vi.fn(async () => "task-r") });
    const r = await runVcenterSnapshotRemove(deps({}, client), { snapshots: SNAPS });
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("vcenter_snapshot_remove:removed");
    expect(r.message).toContain("removed=2");
    expect(r.message).toContain("ids=1,2");
    expect(client.removeSnapshot).toHaveBeenCalledTimes(2);
  });

  it("reports partial success rather than losing the ones that worked", async () => {
    // Anything left behind keeps growing against the datastore, so the backend
    // must learn exactly which rows are now clean.
    const client = fakeClient({
      removeSnapshot: vi.fn(async (moref: string) => {
        if (moref === "snapshot-2") throw new VimFault("VM is busy");
        return "task-r";
      }),
    });
    const r = await runVcenterSnapshotRemove(deps({}, client), { snapshots: SNAPS });
    expect(r.message).toContain("vcenter_snapshot_remove:partial");
    expect(r.message).toContain("removed=1");
    expect(r.message).toContain("failed=1");
    expect(r.message).toContain("failedIds=2");
    expect(r.status).toBe(ACK_RETRY);
  });

  it("treats an already-deleted snapshot as cleaned", async () => {
    const client = fakeClient({
      removeSnapshot: vi.fn(async () => { throw new VimFault("The object has already been deleted"); }),
    });
    const r = await runVcenterSnapshotRemove(deps({}, client), { snapshots: [SNAPS[0]] });
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("removed=1");
  });

  it("respects the configured concurrency ceiling", async () => {
    let inFlight = 0;
    let peak = 0;
    const client = fakeClient({
      removeSnapshot: vi.fn(async () => {
        peak = Math.max(peak, ++inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight--;
        return "task-r";
      }),
    });
    const cfg = { ...CFG, snapshot: { ...CFG.snapshot, maxConcurrent: 2 } };
    const many = Array.from({ length: 8 }, (_, i) => ({
      snapshotResultId: i + 1, deploymentId: 1, targetDeviceId: `d${i}`, snapshotMoref: `snapshot-${i}`,
    }));
    await runVcenterSnapshotRemove(deps({ gatewayConfig: () => cfg }, client), { snapshots: many });
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("no-ops on an empty batch without contacting vCenter", async () => {
    const client = fakeClient();
    const r = await runVcenterSnapshotRemove(deps({}, client), { snapshots: [] });
    expect(r.status).toBe(ACK_OK);
    expect(client.login).not.toHaveBeenCalled();
  });

  it("reports removed=0 when the session itself fails", async () => {
    const client = fakeClient({ login: vi.fn(async () => { throw new Error("ECONNREFUSED"); }) });
    const r = await runVcenterSnapshotRemove(deps({}, client), { snapshots: SNAPS });
    expect(r.message).toContain("removed=0");
    expect(r.status).toBe(ACK_RETRY);
  });

  it("refuses on a device that is not a gateway", async () => {
    const r = await runVcenterSnapshotRemove(deps({ gatewayConfig: () => null }), { snapshots: SNAPS });
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("not_a_gateway");
  });
});

describe("runVcenterSnapshotRevert — operator-initiated only", () => {
  it("reverts the named snapshot", async () => {
    const client = fakeClient({ revertToSnapshot: vi.fn(async () => "task-v") });
    const r = await runVcenterSnapshotRevert(deps({}, client), {
      snapshotResultId: 7, snapshotMoref: "snapshot-13889",
    });
    expect(r.status).toBe(ACK_OK);
    expect(r.message).toContain("vcenter_snapshot_revert:reverted");
    expect(r.message).toContain("snapshotId=snapshot-13889");
    expect(client.revertToSnapshot).toHaveBeenCalledWith("snapshot-13889");
  });

  it("refuses without an explicit snapshot — never guesses which one", async () => {
    const client = fakeClient();
    const r = await runVcenterSnapshotRevert(deps({}, client), {});
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("no_snapshot");
    expect(client.revertToSnapshot).not.toHaveBeenCalled();
  });

  it("does not retry a privilege failure", async () => {
    const client = fakeClient({
      revertToSnapshot: vi.fn(async () => { throw new Error("Permission to perform this operation was denied."); }),
    });
    const r = await runVcenterSnapshotRevert(deps({}, client), { snapshotMoref: "snapshot-1" });
    expect(r.status).toBe(ACK_REJECTED);
    expect(r.message).toContain("insufficient_privileges");
  });

  it("always logs out", async () => {
    const client = fakeClient({ revertToSnapshot: vi.fn(async () => { throw new VimFault("busy"); }) });
    await runVcenterSnapshotRevert(deps({}, client), { snapshotMoref: "snapshot-1" });
    expect(client.logout).toHaveBeenCalled();
  });
});
