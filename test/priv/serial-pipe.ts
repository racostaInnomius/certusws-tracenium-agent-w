// test/priv/serial-pipe.ts
//
// Shared stand-in for the Windows named pipe used by the IPC lane tests.
import { EventEmitter } from "events";

/**
 * A stand-in for the Windows named pipe that reproduces the property that
 * matters: strictly serial service. One request is handled at a time and
 * the next is not even looked at until the previous answer is written.
 */
export class SerialPipe extends EventEmitter {
  destroyed = false;
  writable = true;
  /** method -> how long its "handler" takes. */
  handlerMs: Record<string, number> = {};
  /**
   * Optional: privsvc abandons a wedged handler and starts serving again
   * after this long, without ever answering the request it dropped.
   */
  freeLaneAfterMs: number | null = null;
  /** Methods in arrival order — what the server actually got to execute. */
  dispatched: string[] = [];

  private inbox: any[] = [];
  private busy = false;

  connect(_path: string) {
    queueMicrotask(() => this.emit("connect"));
    return this;
  }

  write(payload: string) {
    for (const line of payload.split("\n")) {
      if (line.trim()) this.inbox.push(JSON.parse(line));
    }
    this.serve();
    return true;
  }

  private serve() {
    if (this.busy) return;
    const req = this.inbox.shift();
    if (!req) return;

    this.busy = true;
    this.dispatched.push(req.method);

    const handlerMs = this.handlerMs[req.method] ?? 10;

    if (this.freeLaneAfterMs !== null && this.freeLaneAfterMs < handlerMs) {
      setTimeout(() => {
        this.busy = false;
        this.serve(); // lane freed, answer never sent
      }, this.freeLaneAfterMs);
      return;
    }

    setTimeout(() => {
      this.busy = false;
      if (!this.destroyed) {
        this.emit("data", JSON.stringify({ v: 1, id: req.id, ok: true, result: {} }) + "\n");
      }
      this.serve();
    }, handlerMs);
  }

  destroy() {
    this.destroyed = true;
    this.writable = false;
    this.emit("close");
  }

  once(event: string, cb: any) {
    return super.once(event, cb);
  }
}

// The client now opens one connection per lane (control / slow — see
// ipc-slow-lane.test.ts), each strictly serial on the privsvc side. Every
// `new net.Socket()` therefore gets its own SerialPipe, seeded from
// `handlerMs` / `freeLaneAfterMs` as configured by the test BEFORE the
// first call. These tests exercise one lane at a time, so every method in
// a test rides the same lane and `pipe` (the only connection) is it.
