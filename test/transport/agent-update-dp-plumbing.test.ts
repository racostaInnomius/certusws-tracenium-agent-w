// test/transport/agent-update-dp-plumbing.test.ts
//
// The agent does not read the gRPC stream directly. The privsvc holds it and
// rebuilds each control message FIELD BY FIELD before pushing it over IPC:
//
//   backend --gRPC--> privsvc bridge --IPC push--> grpc-client --> grpc-stream
//
// Every hop is a hand-written object literal, so a field nobody copies simply
// ceases to exist — with no error anywhere. That is not hypothetical: the ACK
// message spent months arriving as the literal "OK" for exactly this reason,
// which is why every Windows install landed with served_by NULL.
//
// `dpBaseUrlsJson` had the same hole the moment it was added: the proto and
// both endpoints were correct, and all three bridges dropped it, so the DP
// would never have been used for an agent update. These assertions pin the
// whole chain rather than either end of it.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";

const repoRoot = path.join(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(repoRoot, rel), "utf8");

const FIELD = "dpBaseUrlsJson";

describe("agent_update DP plumbing, end to end", () => {
  it("the proto declares the field", () => {
    const proto = read("proto/controlplane.proto");
    const block = proto.slice(proto.indexOf("message AgentUpdate"));
    expect(block.slice(0, block.indexOf("}"))).toContain(FIELD);
  });

  it("the windows bridge forwards it to the agent", () => {
    // C# reads it off the generated message and must place it in the pushed
    // params object; naming the local variable is not enough.
    const cs = read("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs");
    const at = cs.indexOf("msg.AgentUpdate is not null");
    const block = cs.slice(at, at + 1600);
    expect(block).toMatch(/msg\.AgentUpdate\.DpBaseUrlsJson/);
    // The push payload itself — the part that actually crosses the pipe.
    const push = block.slice(block.indexOf("PushToAll"));
    expect(push).toContain(FIELD);
  });

  it.each(["macos", "linux"])("the %s bridge forwards it to the agent", (platform) => {
    const src = read(`privsvc/${platform}/src/grpc-bridge.ts`);
    const at = src.indexOf('push("grpc.control.agentUpdate"');
    expect(at, `${platform}: no agentUpdate push`).toBeGreaterThan(-1);
    expect(src.slice(at, at + 700)).toContain(`${FIELD}: msg.agentUpdate.${FIELD}`);
  });

  it("grpc-client turns the push back into a control message", () => {
    // The bridge pushes `params`; this is where they become msg.agentUpdate.
    // If this ever started cherry-picking fields it would reintroduce the same
    // class of silent loss one hop later.
    const src = read("src/transport/grpc-client.ts");
    const at = src.indexOf('method === "grpc.control.agentUpdate"');
    expect(at).toBeGreaterThan(-1);
    expect(src.slice(at, at + 240)).toMatch(/agentUpdate:\s*params/);
  });

  it("grpc-stream reads the field and hands it to the updater", () => {
    const src = read("src/transport/grpc-stream.ts");
    expect(src).toMatch(new RegExp(`msg\\.agentUpdate as any\\)\\?\\.${FIELD}`));
    expect(src).toMatch(/dpBaseUrls:\s*parseDpBaseUrls/);
  });

  it("no hop still refers to the abandoned sourcesJson name", () => {
    // It was replaced once the control plane turned out not to know the
    // device's architecture. A leftover reference would mean one hop is
    // reading a field nobody sends.
    for (const rel of [
      "proto/controlplane.proto",
      "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridge.cs",
      "privsvc/macos/src/grpc-bridge.ts",
      "privsvc/linux/src/grpc-bridge.ts",
      "src/transport/grpc-stream.ts",
    ]) {
      expect(read(rel), `${rel} still mentions sourcesJson`).not.toContain("sourcesJson");
    }
  });
});
