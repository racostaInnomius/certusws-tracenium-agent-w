// test/priv/ack-message-forwarding.test.ts
//
// The ACK message is the only channel carrying structured job detail from the
// agent to the control plane, and on Windows it was thrown away.
//
// grpc-stream.ts sends { eventId, status, message } over IPC. GrpcBridge's
// SendAck accepts (eventId, status, message) and substitutes the literal "OK"
// when message is null. IpcGrpcHandlers.HandleAck read only eventId and status,
// so every Windows ACK — for every job type — reached the backend as "OK".
//
// What that cost, silently:
//
//   * SDP. `software_install:<outcome>;exit=..;servedBy=..;reason=..` is the
//     sole source for software_install_results.exit_code, served_by and
//     stderr_excerpt. parseAckMessage cannot match "OK", so the backend fell
//     back to inferring the outcome from the numeric status and every Windows
//     install landed with served_by NULL. During a distribution point test
//     that read as "the DP did not serve the package" when the field had
//     simply never been sent.
//   * agent_update. update_started / update_skipped / update_failed all
//     arrived as "OK", erasing the distinction the outcome contract exists for.
//
// macOS and Linux always forwarded it. The point of this test is the parity:
// three privsvc implementations, one contract, and only cross-checking them
// catches a limb that quietly stops carrying a field.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const repoRoot = path.join(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(repoRoot, rel), "utf8");

describe("grpc.ack forwards the agent's message on every platform", () => {
  it("the agent actually sends a message field", () => {
    const src = read("src/transport/grpc-stream.ts");
    const at = src.indexOf('"grpc.ack"');
    expect(at, "no grpc.ack call in the agent").toBeGreaterThan(-1);
    expect(src.slice(at, at + 400)).toMatch(/\bmessage\b/);
  });

  it("windows reads message from the IPC params and passes it to SendAck", () => {
    const cs = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/IpcGrpcHandlers.cs");
    const at = cs.indexOf("public static async Task<PrivSvcResponse> HandleAck");
    expect(at, "HandleAck not found").toBeGreaterThan(-1);
    const body = cs.slice(at, at + 2500);

    expect(body, 'HandleAck must read GetString(p, "message")').toMatch(
      /GetString\(p,\s*"message"\)/
    );
    // The bug was the call site, not the parsing: SendAck(eventId, status)
    // compiles fine because message is an optional parameter.
    expect(body, "SendAck must be given the message").toMatch(
      /SendAck\(\s*eventId\s*,\s*status\s*,\s*message/
    );
  });

  it.each(["macos", "linux"])("%s forwards message in its ack frame", (platform) => {
    const src = read(`privsvc/${platform}/src/grpc-bridge.ts`);
    const at = src.indexOf("export async function handleAck");
    expect(at, `${platform}: handleAck not found`).toBeGreaterThan(-1);
    expect(src.slice(at, at + 900)).toMatch(/message:\s*String\(req\.params\?\.message/);
  });
});
