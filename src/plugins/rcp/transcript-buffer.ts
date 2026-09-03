// src/plugins/rcp/transcript-buffer.ts
//
// RCP M1.S3 — buffers PTY stdout into time-stamped chunks and
// flushes them to the backend via gRPC every ~5 seconds or when
// the buffer reaches ~8 KB, whichever triggers first.
//
// Why buffered (not per-chunk):
//   - A noisy shell session (`tail -f` on a log) emits hundreds of
//     tiny chunks per second. Sending one gRPC message per chunk
//     would be ~150 KB/s of message overhead on top of the actual
//     payload, and would create a thundering-herd on the audit
//     persistence path.
//   - The asciinema v2 format only needs an absolute timestamp on
//     each event line — we synthesize that from the buffer's
//     "start of buffering" timestamp + offset, even after we
//     coalesce.
//
// Coalescing rule:
//   - Output that arrives within the same flush window gets
//     concatenated into ONE chunk with a single ts_delta_seconds
//     value pointing to the START of the buffered content. This
//     loses sub-flush-window timing detail but keeps the replay
//     visually correct (you see the same scroll as the operator
//     did) — the operator wasn't perceiving sub-50ms timing
//     differences anyway.
//
// What we DON'T buffer here:
//   - stdin. Sprint 3 only captures stdout; see migration doc.
//   - control messages (resize/close). Those are session
//     lifecycle events, not transcript content.

const FLUSH_INTERVAL_MS = 5_000;
const FLUSH_THRESHOLD_BYTES = 8 * 1024;
// Hard cap per chunk. Asciinema players don't enjoy multi-MB
// events; 64 KB matches the DB column documentation and is the
// largest a slow viewer can render without freezing.
const MAX_CHUNK_BYTES = 64 * 1024;

type FlushFn = (chunk: {
  stream: "stdout";
  tsDeltaSeconds: number;
  data: string;
  bytesCount: number;
}) => void;

export class TranscriptBuffer {
  private buffer = "";
  private bufferBytes = 0;
  // Wall-clock timestamp (ms) of the FIRST byte buffered this
  // flush cycle. Becomes the ts_delta_seconds origin once we
  // serialize.
  private bufferStartMs: number | null = null;
  private flushTimer: NodeJS.Timeout | null = null;
  private disposed = false;

  constructor(
    /** Absolute time when the session started (transcript origin). */
    private readonly sessionStartedAtMs: number,
    /** Called once per coalesced chunk. The agent wires this into
     * a gRPC send on the existing control stream. */
    private readonly flushFn: FlushFn
  ) {}

  /**
   * Append a chunk of stdout to the buffer. The chunk may itself
   * be larger than the flush threshold (rare — usually small
   * keystroke echoes) in which case we flush IMMEDIATELY and
   * potentially split into multiple sends.
   */
  append(data: string): void {
    if (this.disposed) return;
    if (!data) return;
    if (this.bufferStartMs === null) {
      this.bufferStartMs = Date.now();
      this.armTimer();
    }
    // UTF-8 byte length, not character count. Long-form approx is
    // good enough; we don't need exactness, just a heuristic.
    const inboundBytes = Buffer.byteLength(data, "utf-8");
    if (inboundBytes > MAX_CHUNK_BYTES) {
      // Single shell write exceeded the cap — flush the existing
      // buffer first, then send this chunk in slices.
      this.flush();
      this.sliceAndSendOversize(data);
      return;
    }
    this.buffer += data;
    this.bufferBytes += inboundBytes;
    if (this.bufferBytes >= FLUSH_THRESHOLD_BYTES) {
      this.flush();
    }
  }

  /**
   * Force any buffered content out NOW. Called from PtySession on
   * shell exit so the last partial flush still gets persisted.
   * Also called by the flush timer.
   */
  flush(): void {
    if (this.disposed) return;
    if (this.buffer.length === 0 || this.bufferStartMs === null) {
      this.clearTimer();
      return;
    }
    const tsDeltaSeconds =
      Math.max(0, this.bufferStartMs - this.sessionStartedAtMs) / 1000;
    try {
      this.flushFn({
        stream: "stdout",
        tsDeltaSeconds,
        data: this.buffer,
        bytesCount: this.bufferBytes
      });
    } catch {
      // Flush failures are swallowed — the audit log is best-effort
      // for individual chunks. Repeated failures degrade the
      // transcript completeness but do NOT take down the shell.
    }
    this.buffer = "";
    this.bufferBytes = 0;
    this.bufferStartMs = null;
    this.clearTimer();
  }

  /**
   * End of session: emit whatever is still buffered, then refuse further
   * output.
   *
   * ⚠️ The flush happens BEFORE `disposed` goes true, and the order is the
   * entire point. flush() bails on `disposed`, so setting the flag first —
   * which is what this method used to do — made the final flush a no-op and
   * silently threw away everything since the last 5-second/8 KB trigger.
   * That is the tail of every shell session: the last commands, which is the
   * part an auditor opens the replay to see.
   *
   * The same mistake existed one layer up, in PeerSession.dispose(): both
   * had to be fixed for a single byte of the tail to survive.
   */
  dispose(): void {
    if (this.disposed) return;
    this.flush();
    this.disposed = true;
    this.clearTimer();
  }

  // ── Internals ─────────────────────────────────────────────────

  private armTimer(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush();
    }, FLUSH_INTERVAL_MS);
    // Don't keep the process alive just for the transcript timer.
    (this.flushTimer as any).unref?.();
  }

  private clearTimer(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * One-off path for an oversize chunk (single write > 64 KB).
   * Splits into MAX_CHUNK_BYTES slices, each its own send with a
   * tsDeltaSeconds tied to the slice's logical position. We
   * don't try to be precise about per-slice timing — the operator
   * didn't perceive sub-millisecond ordering of bytes within ONE
   * shell write.
   */
  private sliceAndSendOversize(data: string): void {
    const startedAt = Date.now();
    const tsDeltaSeconds =
      Math.max(0, startedAt - this.sessionStartedAtMs) / 1000;
    // Slice in character boundaries. JS strings are UTF-16; this
    // can split a surrogate pair if a code point straddles the
    // boundary. xterm.js renders mojibake gracefully; for the
    // common ASCII-heavy case this is irrelevant.
    let offset = 0;
    while (offset < data.length) {
      const slice = data.slice(offset, offset + MAX_CHUNK_BYTES);
      const sliceBytes = Buffer.byteLength(slice, "utf-8");
      try {
        this.flushFn({
          stream: "stdout",
          tsDeltaSeconds,
          data: slice,
          bytesCount: sliceBytes
        });
      } catch {
        /* see flush() */
      }
      offset += MAX_CHUNK_BYTES;
    }
  }
}
