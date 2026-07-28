// test/plugins/rcp-screen-dirty-rects.test.ts
//
// Dirty-rect streaming makes screen frames INTERDEPENDENT: most carry only
// the region that changed, blitted onto whatever the browser already has.
// Over a deliberately unreliable DataChannel (ordered:false,
// maxRetransmits:0) that only works if full frames keep arriving, so the
// keyframe contract is the thing worth pinning down:
//
//   - the first capture of a session must be full (browser has no pixels)
//   - captures inside the keyframe interval may be partial
//   - region metadata reaches the browser intact
//   - a PrivSvc response with no region info counts as FULL, never as a
//     partial sitting at (0,0) — that's what macOS/Linux helpers return
//
// The capture loop is driven by real timers at fps=5 (200 ms/frame), so the
// tests wait rather than mock the clock; the alternative is faking timers
// around an async IPC call, which tests the mock more than the code.

import { describe, it, expect, vi } from "vitest";
import { ScreenSession } from "../../src/plugins/rcp/screen-session";

class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  private closedCb: (() => void) | null = null;
  sent: string[] = [];
  onMessage(cb: (raw: any) => void) { this.msgCb = cb; }
  onClosed(cb: () => void) { this.closedCb = cb; }
  sendMessage(text: string) { this.sent.push(text); }
  emit(obj: any) { this.msgCb?.(JSON.stringify(obj)); }
  triggerClosed() { this.closedCb?.(); }
  parsed(): any[] { return this.sent.map((s) => JSON.parse(s)); }
  ofOp(op: string): any[] { return this.parsed().filter((m) => m.op === op); }
}

/** Build a session whose PrivSvc returns whatever `results` yields. */
function makeSession(results: (call: any) => any) {
  const dc = new FakeDataChannel();
  const calls: any[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    priv: {
      call: vi.fn(async (req: any) => {
        calls.push(req);
        return results(req);
      })
    }
  };
  const session = new ScreenSession(dc as any, {
    sessionId: "sess-screen-abcdef",
    ctx,
    sendScreenAudit: () => {},
    onTeardown: () => {}
  });
  return { dc, calls, session };
}

const okFrame = (over: Record<string, unknown> = {}) => ({
  ok: true,
  result: {
    data: "QUJD", // "ABC"
    width: 1920,
    height: 1080,
    cursorX: 10,
    cursorY: 20,
    full: true,
    x: 0,
    y: 0,
    rw: 1920,
    rh: 1080,
    ...over
  }
});

async function waitFor(cond: () => boolean, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return;
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("screen dirty rects — keyframe contract", () => {
  it("asks for a FULL frame on the very first capture", async () => {
    const { calls, session } = makeSession(() => okFrame());
    await waitFor(() => calls.length >= 1);
    expect(calls[0].params.forceFull).toBe(true);
    session.dispose("test");
  });

  it("stops forcing full once a keyframe has gone out", async () => {
    // Second and later captures inside the interval let DXGI decide, which
    // is where the bandwidth win comes from.
    const { calls, session } = makeSession(() => okFrame());
    await waitFor(() => calls.length >= 3);
    expect(calls[0].params.forceFull).toBe(true);
    expect(calls[1].params.forceFull).toBe(false);
    expect(calls[2].params.forceFull).toBe(false);
    session.dispose("test");
  });

  it("keeps forcing full while PrivSvc never delivers one", async () => {
    // If the device only ever answers with partials, the keyframe timer must
    // not advance — otherwise the browser would never get a base image.
    const { calls, session } = makeSession(() =>
      okFrame({ full: false, x: 4, y: 8, rw: 16, rh: 16 })
    );
    await waitFor(() => calls.length >= 3);
    expect(calls.every((c) => c.params.forceFull === true)).toBe(true);
    session.dispose("test");
  });
});

describe("screen dirty rects — what reaches the browser", () => {
  it("forwards the region and keeps width/height as the FULL desktop", async () => {
    const { dc, session } = makeSession(() =>
      okFrame({ full: false, x: 100, y: 200, rw: 64, rh: 32 })
    );
    await waitFor(() => dc.ofOp("frame").length >= 1);
    const f = dc.ofOp("frame")[0];
    expect(f.full).toBe(false);
    expect(f.x).toBe(100);
    expect(f.y).toBe(200);
    expect(f.rw).toBe(64);
    expect(f.rh).toBe(32);
    // Canvas sizing + input coordinate mapping depend on these being the
    // whole desktop, not the region.
    expect(f.width).toBe(1920);
    expect(f.height).toBe(1080);
    session.dispose("test");
  });

  it("treats a response with no region info as a FULL frame", async () => {
    // macOS and Linux helpers only do whole-screen grabs and never send
    // `full`. Defaulting to partial would blit the whole desktop at (0,0)
    // and, worse, never reset the keyframe clock.
    const { dc, session } = makeSession(() => ({
      ok: true,
      result: { data: "QUJD", width: 1280, height: 800, cursorX: -1, cursorY: -1 }
    }));
    await waitFor(() => dc.ofOp("frame").length >= 1);
    const f = dc.ofOp("frame")[0];
    expect(f.full).toBe(true);
    expect(f.x).toBe(0);
    expect(f.y).toBe(0);
    expect(f.rw).toBe(1280);
    expect(f.rh).toBe(800);
    session.dispose("test");
  });

  it("puts the region on frameStart when a frame has to be chunked", async () => {
    const big = "A".repeat(60_000); // > FRAME_CHUNK_MAX
    const { dc, session } = makeSession(() =>
      okFrame({ data: big, full: false, x: 7, y: 9, rw: 300, rh: 200 })
    );
    await waitFor(() => dc.ofOp("frameStart").length >= 1);
    const start = dc.ofOp("frameStart")[0];
    expect(start.full).toBe(false);
    expect(start.x).toBe(7);
    expect(start.y).toBe(9);
    expect(dc.ofOp("frameChunk").length).toBeGreaterThan(0);
    // Chunks stay payload-only — the browser reads geometry off frameStart.
    expect(dc.ofOp("frameChunk")[0].x).toBeUndefined();
    session.dispose("test");
  });
});
