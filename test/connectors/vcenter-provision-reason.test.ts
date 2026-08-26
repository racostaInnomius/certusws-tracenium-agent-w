// test/connectors/vcenter-provision-reason.test.ts
//
// A sealed vCenter credential failed on a production gateway with exactly one
// word of diagnosis: `vcenter_credential_provision:decrypt_failed`.
//
// PrivSvc knew far more than that. It distinguishes three unrelated causes and
// sends its own fixed message with the code:
//
//   "certificate has no usable private key" — the cert sits in the Windows
//       store without its key, or the service account cannot reach the KSP.
//       The password is irrelevant; re-entering it cannot possibly help.
//   "could not unwrap the envelope key"     — the private key does not match
//       the certificate the browser sealed against.
//   "envelope failed authentication"        — key fine, contents or the
//       fingerprint binding wrong.
//
// The message reached the agent and was dropped one line before the ACK. These
// tests pin that it survives, and that it survives in a form the ACK's
// `k=v;k=v` body can actually carry.

import { describe, it, expect } from "vitest";
import { buildProvisionAck } from "../../src/connectors/vcenter/ack";

/** The three messages PrivSvc actually sends for this code. */
const PRIVSVC_MESSAGES = [
  "certificate has no usable private key",
  "could not unwrap the envelope key",
  "envelope failed authentication",
];

describe("provision ack carries PrivSvc's reason", () => {
  it.each(PRIVSVC_MESSAGES)("keeps %s in the ack", (reason) => {
    const ack = buildProvisionAck("decrypt_failed", { reason });
    expect(ack.message).toContain("vcenter_credential_provision:decrypt_failed");
    expect(ack.message).toContain(reason);
  });

  it("distinguishes the three causes from one another", () => {
    // The whole point: three different ACKs, not three copies of one word.
    const messages = PRIVSVC_MESSAGES.map(
      (reason) => buildProvisionAck("decrypt_failed", { reason }).message
    );
    expect(new Set(messages).size).toBe(3);
  });

  it("still reads as a rejection, not a retryable failure", () => {
    // Adding detail must not change how the control plane classifies it: a
    // credential that cannot be opened will not open on a retry.
    const withReason = buildProvisionAck("decrypt_failed", { reason: PRIVSVC_MESSAGES[0] });
    const without = buildProvisionAck("decrypt_failed");
    expect(withReason.status).toBe(without.status);
  });

  it("does not break the k=v body when a reason contains separators", () => {
    // The ACK body is `k=v;k=v`. A raw `;` or newline would split into a field
    // nobody parses and could silently truncate what follows.
    const ack = buildProvisionAck("decrypt_failed", {
      reason: "bad key; really bad\nand multiline",
    });
    const body = ack.message.split("vcenter_credential_provision:decrypt_failed;")[1] ?? "";
    expect(body).not.toContain("\n");
    // One field only: the reason, not a reason plus fragments of itself.
    expect(body.split(";").filter(Boolean).length).toBe(1);
  });

  it("omits the reason entirely when there is none", () => {
    const ack = buildProvisionAck("decrypt_failed");
    expect(ack.message).toBe("vcenter_credential_provision:decrypt_failed");
  });
});
