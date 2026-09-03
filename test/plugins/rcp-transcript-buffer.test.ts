// test/plugins/rcp-transcript-buffer.test.ts
//
// TranscriptBuffer holds the evidence for a shell session and had no tests.
//
// ⚠️ The bug that prompted these: replaying the last shell session showed
// output that stopped before the end. The buffer flushes every 5 s or every
// 8 KB, so everything after the last trigger lives ONLY in memory until
// dispose() flushes it — and peer-session was closing its send path before
// calling dispose(), so that final flush was discarded on every session. The
// property these tests pin is the one that fix depends on: dispose() emits
// what is still buffered.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TranscriptBuffer } from "../../src/plugins/rcp/transcript-buffer";

type Chunk = { stream: "stdout"; tsDeltaSeconds: number; data: string; bytesCount: number };

const START = 1_000_000;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(START);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("what dispose() must do", () => {
  it("⚠️ flushes what is still buffered", async () => {
    // This is the whole evidence chain: the last thing an operator typed
    // usually arrives less than 5 seconds and less than 8 KB before the
    // session closes, so it is sitting in this buffer and nowhere else.
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("whoami\r\nroot\r\n");
    expect(sent).toHaveLength(0); // still buffered — no trigger hit

    buf.dispose();

    expect(sent).toHaveLength(1);
    expect(sent[0].data).toBe("whoami\r\nroot\r\n");
  });

  it("does not emit an empty chunk when there is nothing buffered", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));
    buf.dispose();
    expect(sent).toHaveLength(0);
  });

  it("is idempotent — a second dispose sends nothing more", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));
    buf.append("ls -la\r\n");
    buf.dispose();
    buf.dispose();
    expect(sent).toHaveLength(1);
  });

  it("stops accepting output once disposed", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));
    buf.dispose();
    buf.append("this arrived after the session ended");
    expect(sent).toHaveLength(0);
  });
});

describe("the flush triggers", () => {
  it("flushes on the 5-second timer", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("slow output");
    vi.advanceTimersByTime(4_999);
    expect(sent).toHaveLength(0);

    vi.advanceTimersByTime(2);
    expect(sent).toHaveLength(1);
    expect(sent[0].data).toBe("slow output");
  });

  it("flushes as soon as the buffer passes 8 KB", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("x".repeat(8 * 1024 - 1));
    expect(sent).toHaveLength(0);

    buf.append("yy");
    expect(sent).toHaveLength(1);
    expect(sent[0].bytesCount).toBe(8 * 1024 + 1);
  });

  it("⚠️ the timer does not re-arm across an empty window", async () => {
    // A shell that goes quiet must not keep waking the process every 5 s for
    // the rest of the session — this is an agent that lives for months.
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("one burst");
    vi.advanceTimersByTime(5_001);
    expect(sent).toHaveLength(1);

    vi.advanceTimersByTime(60_000);
    expect(sent).toHaveLength(1);
  });
});

describe("timing in the replay", () => {
  it("stamps the chunk at the moment its FIRST byte arrived", async () => {
    // Not the flush time. Stamping at flush would push every line of a burst
    // to the end of its 5-second window and make the replay stutter.
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    vi.setSystemTime(START + 2_000);
    buf.append("typed at t+2");
    vi.setSystemTime(START + 6_500);
    buf.dispose();

    expect(sent[0].tsDeltaSeconds).toBe(2);
  });

  it("never emits a negative offset for output that predates the origin", async () => {
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START + 5_000, (c) => sent.push(c));
    buf.append("clock skew");
    buf.dispose();
    expect(sent[0].tsDeltaSeconds).toBe(0);
  });
});

describe("a single oversize write", () => {
  it("is split rather than dropped", async () => {
    // `cat` of a large file arrives as one write. Dropping it would leave a
    // hole in the transcript exactly where the interesting thing happened.
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("z".repeat(150 * 1024));

    expect(sent.length).toBeGreaterThan(1);
    expect(sent.map((c) => c.data).join("")).toHaveLength(150 * 1024);
  });

  it("flushes what was already buffered BEFORE the oversize write", async () => {
    // Otherwise the big write would jump ahead of the output that preceded
    // it, and the replay would show them out of order.
    const sent: Chunk[] = [];
    const buf = new TranscriptBuffer(START, (c) => sent.push(c));

    buf.append("prompt$ cat big.log\r\n");
    buf.append("z".repeat(150 * 1024));

    expect(sent[0].data).toBe("prompt$ cat big.log\r\n");
  });
});

describe("a failing send", () => {
  it("⚠️ does not take the shell down with it", async () => {
    // The transcript is best-effort per chunk: an audit gap is bad, killing
    // the operator's session mid-command is worse.
    const buf = new TranscriptBuffer(START, () => {
      throw new Error("control stream is down");
    });

    expect(() => {
      buf.append("still typing");
      buf.dispose();
    }).not.toThrow();
  });
});
