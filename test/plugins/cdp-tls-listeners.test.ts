// test/plugins/cdp-tls-listeners.test.ts
//
// The TLS listener collector. Two halves:
//
//   * Port parsing — pure, table-driven against real /proc and netstat
//     output shapes. Getting the loopback filter wrong either misses
//     every service or probes ports 127.0.0.1 cannot reach.
//   * The probe itself — exercised against a REAL TLS server started
//     inside the test, because a mocked handshake would prove nothing
//     about the thing this collector exists to do: read the certificate
//     a service actually serves.

import { describe, it, expect, afterEach } from "vitest";
import tls from "tls";
import net from "net";
import { parseProcNetTcp, parseNetstat } from "../../src/plugins/cdp/listening-ports";
import {
  probeTlsPort,
  collectTlsListeners,
  SKIPPED_PORTS
} from "../../src/plugins/cdp/providers/tls-listeners";
import type { AgentContext } from "../../src/core/agent-context";
import { FIXTURE_KEY, FIXTURE_CERT } from "./tls-fixture";

function makeCtx(overrides: Record<string, any> = {}): AgentContext {
  return {
    policyRuntime: {
      getCdpScanTlsListeners: () => true,
      getCdpTlsListenerPorts: () => [],
      ...overrides
    },
    logger: { info: () => {}, warn: () => {}, debug: () => {} }
  } as unknown as AgentContext;
}

describe("parseProcNetTcp", () => {
  const header =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

  it("keeps wildcard and loopback listeners", () => {
    const table =
      header +
      "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n" + // 0.0.0.0:443
      "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n";  // 127.0.0.1:8080
    expect(parseProcNetTcp(table).sort((a, b) => a - b)).toEqual([443, 8080]);
  });

  it("drops non-LISTEN sockets", () => {
    const established =
      header +
      "   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 3\n";
    expect(parseProcNetTcp(established)).toEqual([]);
  });

  it("drops listeners bound to an interface 127.0.0.1 cannot reach", () => {
    // 0201A8C0 = 192.168.1.2 in little-endian hex.
    const external =
      header +
      "   0: 0201A8C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4\n";
    expect(parseProcNetTcp(external)).toEqual([]);
  });

  it("survives junk without throwing", () => {
    expect(parseProcNetTcp("")).toEqual([]);
    expect(parseProcNetTcp("garbage\nmore garbage")).toEqual([]);
  });
});

describe("parseNetstat", () => {
  it("parses the BSD/macOS format", () => {
    const out = [
      "Active Internet connections (including servers)",
      "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
      "tcp4       0      0  127.0.0.1.8443         *.*                    LISTEN",
      "tcp4       0      0  *.443                  *.*                    LISTEN",
      "tcp4       0      0  192.168.1.5.9000       *.*                    LISTEN",
      "tcp4       0      0  127.0.0.1.52344        127.0.0.1.8443         ESTABLISHED"
    ].join("\n");
    expect(parseNetstat(out).sort((a, b) => a - b)).toEqual([443, 8443]);
  });

  it("parses the Windows format", () => {
    const out = [
      "Active Connections",
      "  Proto  Local Address          Foreign Address        State",
      "  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING",
      "  TCP    127.0.0.1:5985         0.0.0.0:0              LISTENING",
      "  TCP    10.0.0.4:3389          0.0.0.0:0              LISTENING",
      "  TCP    127.0.0.1:49670        127.0.0.1:443          ESTABLISHED"
    ].join("\n");
    expect(parseNetstat(out).sort((a, b) => a - b)).toEqual([443, 5985]);
  });

  it("returns nothing for empty or malformed input", () => {
    expect(parseNetstat("")).toEqual([]);
    expect(parseNetstat("no listeners here")).toEqual([]);
  });
});

describe("probeTlsPort against real sockets", () => {
  const closers: Array<() => void> = [];
  afterEach(() => {
    while (closers.length) closers.pop()!();
  });

  function startTlsServer(): Promise<number> {
    return new Promise((resolve) => {
      const server = tls.createServer(
        { key: FIXTURE_KEY, cert: FIXTURE_CERT },
        (s) => s.end()
      );
      server.listen(0, "127.0.0.1", () => {
        closers.push(() => server.close());
        resolve((server.address() as net.AddressInfo).port);
      });
    });
  }

  function startPlainServer(): Promise<number> {
    return new Promise((resolve) => {
      const server = net.createServer((s) => s.end());
      server.listen(0, "127.0.0.1", () => {
        closers.push(() => server.close());
        resolve((server.address() as net.AddressInfo).port);
      });
    });
  }

  it("captures the certificate a real TLS service serves", async () => {
    const port = await startTlsServer();
    const der = await probeTlsPort(port);
    expect(der).toBeInstanceOf(Buffer);
    expect(der!.length).toBeGreaterThan(0);
  });

  it("returns null for a plaintext listener instead of hanging or throwing", async () => {
    const port = await startPlainServer();
    expect(await probeTlsPort(port)).toBeNull();
  });

  it("returns null for a closed port", async () => {
    const port = await startPlainServer();
    closers.pop()!(); // close it before probing
    expect(await probeTlsPort(port)).toBeNull();
  });

  it("turns a live listener into an inventory item marked as a listener", async () => {
    const port = await startTlsServer();
    const result = await collectTlsListeners(makeCtx(), { ports: [port] });

    expect(result.portsScanned).toBe(1);
    expect(result.portsWithTls).toBe(1);
    expect(result.items).toHaveLength(1);

    const item = result.items[0];
    expect(item.source).toBe("listener");
    expect(item.store.id).toBe(`listener/tcp/${port}`);
    // Machine scope on purpose: a served cert must reach the default
    // views and the expiry alert, unlike a trust-store root.
    expect(item.store.scope).toBe("machine");
    expect(item.fingerprint256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("collectTlsListeners scoping", () => {
  const probeCalls: number[] = [];
  const trackingProbe = async (port: number) => {
    probeCalls.push(port);
    return null;
  };

  it("never probes the skip list", async () => {
    probeCalls.length = 0;
    const risky = [22, 3306, 5432, 27017];
    const result = await collectTlsListeners(makeCtx(), {
      ports: [...risky, 8443],
      probe: trackingProbe
    });
    expect(probeCalls).toEqual([8443]);
    expect(result.portsScanned).toBe(1);
    for (const p of risky) expect(SKIPPED_PORTS.has(p)).toBe(true);
  });

  it("honours an explicit port list as 'only these'", async () => {
    probeCalls.length = 0;
    await collectTlsListeners(
      makeCtx({ getCdpTlsListenerPorts: () => [8443] }),
      { ports: [443, 8443, 9443], probe: trackingProbe }
    );
    expect(probeCalls).toEqual([8443]);
  });

  it("does no work when nothing is listening", async () => {
    probeCalls.length = 0;
    const result = await collectTlsListeners(makeCtx(), { ports: [], probe: trackingProbe });
    expect(probeCalls).toEqual([]);
    expect(result.items).toEqual([]);
  });
});
