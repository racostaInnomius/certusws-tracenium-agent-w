// privsvc/linux/src/index.ts
//
// Daemon entry. Same shape as the macOS index — the setBlocking()
// dance is platform-independent (the underlying issue was Node's
// libuv buffering stdout writes when stdout is a pipe rather than a
// TTY, regardless of which init system feeds the pipe). On Linux,
// systemd's StandardOutput=journal hooks the daemon's stdout into a
// journald socket — that's a non-TTY pipe, so the same buffering
// pathology applies and the same fix works.
import { startServer } from "./server";

// Patch F (May 2026 incident, ported from macOS) — force stdout/stderr
// to be blocking so log lines don't sit in libuv's 16KB block buffer
// for hours.
//
// Symptom on macOS that motivated this: privsvc.stdout.log went silent
// for 80 minutes during a real zombie scenario, even though timer-
// based events (watchdog ticks, would-be teardowns, breaker trips)
// clearly fired. The events were happening but their log lines were
// trapped in a buffered FIFO that never drained because Node only
// flushes on (a) buffer-full, (b) process exit, or (c) explicit
// fsync — and the daemon ran for hours without hitting any of those.
//
// systemd's journald reads stdout via an AF_UNIX SOCK_DGRAM socket
// (or a pipe, depending on systemd version). Either way it's a non-
// TTY, so libuv's heuristic for "is this interactive?" picks
// non-blocking + buffered. setBlocking(true) overrides that. Cost is
// per-write blocking for the small JSON-line traffic we emit; the
// dedicated file under LOG_DIR is sync via appendFileSync anyway, so
// there's no scenario where this matters for write throughput.
try {
  (process.stdout as any)?._handle?.setBlocking?.(true);
  (process.stderr as any)?._handle?.setBlocking?.(true);
} catch {
  // Older Node builds may not expose _handle on the writable streams;
  // best-effort. The dedicated file in LOG_DIR remains the canonical
  // record either way.
}

startServer();
