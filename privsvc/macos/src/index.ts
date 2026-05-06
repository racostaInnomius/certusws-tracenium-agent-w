import { startServer } from "./server";

// ── Patch F (May 2026 incident) — force stdout/stderr to be blocking
// so log lines don't sit in a 16KB block buffer for hours.
//
// Symptom: privsvc.stdout.log went silent for 80 minutes during a
// real zombie scenario, even though timer-based events (watchdog
// ticks, would-be teardowns, breaker trips) clearly fired. The events
// were happening but their log lines were trapped in a buffered FIFO
// that never drained because Node only flushes on (a) buffer-full,
// (b) process exit, or (c) explicit fsync — and the daemon ran for
// hours without hitting any of those. We were debugging blind.
//
// `setBlocking(true)` makes process.stdout/stderr write synchronously
// like a TTY would, so each `console.log(...)` lands on disk
// immediately. Cost is per-write blocking for the small amount of
// stdout traffic we generate (JSON-line records, not high-
// throughput data). Benefit: incident-time forensics are possible.
//
// We ALSO tee logs to /Library/Logs/Tracenium/tracenium-privsvc-macos.log
// via fs.appendFileSync in logger.ts (sync = no buffering issue),
// but the launchd-captured stdout file is what an operator hits
// first via `tail`, so it has to be reliable too.
try {
  (process.stdout as any)?._handle?.setBlocking?.(true);
  (process.stderr as any)?._handle?.setBlocking?.(true);
} catch {
  // Older Node builds may not expose _handle on the writable streams;
  // best-effort. The dedicated file in LOG_DIR remains the canonical
  // record either way.
}

startServer();
