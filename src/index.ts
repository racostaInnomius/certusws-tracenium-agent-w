// src/index.ts
import { startService } from "./core/service";

// ── Crash containment ─────────────────────────────────────────────
//
// Without explicit handlers, Node treats `uncaughtException` and (since
// Node 15) `unhandledRejection` as fatal — the process exits silently
// with no stderr/stdout flush of the offending stack. That has bitten
// us for months as "the AgentCore service mysteriously stops running":
// any rare codepath that throws past a promise boundary (a malformed
// proto message, a native module returning a rejected promise we don't
// `await`, etc.) takes the whole process down. WinSW then either
// restarts us or — if the rate-limit kicks in — leaves the service
// in Stopped state until the next reboot.
//
// We learned this concretely with RCP: the operator clicks Shell, the
// agent logs `[rcp] initialized`, and then `.out` goes silent forever
// while PrivSvc (a SEPARATE C# service that owns the gRPC connection)
// keeps heartbeating just fine — masking that AgentCore died mid-
// dispatch. From the operator's perspective: "the agent is online but
// nothing works."
//
// Logging + survival is strictly better than silent death:
//   * uncaughtException — log the full error with stack and KEEP RUNNING.
//     The current request fails, but the agent stays up to serve the
//     next one. If we wanted graceful shutdown for "really fatal"
//     errors we'd need to classify by error type, which we can't do
//     blindly; survival is the conservative default.
//   * unhandledRejection — same. Log + survive. (Setting to "warn" via
//     CLI flag is per-invocation; this is per-codebase.)

process.on("uncaughtException", (err) => {
  // Use console.error directly: the logger may itself be the source of
  // the failure, and we can't risk an infinite loop here.
  console.error("[FATAL] uncaughtException — process kept alive", {
    message: err?.message,
    name: err?.name,
    code: (err as any)?.code,
    stack: err?.stack
  });
});

process.on("unhandledRejection", (reason: any) => {
  console.error("[FATAL] unhandledRejection — process kept alive", {
    message: reason?.message,
    name: reason?.name,
    code: reason?.code,
    stack: reason?.stack,
    reason: reason?.message ? undefined : String(reason)
  });
});

startService().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

process.on("SIGTERM", () => {
  console.log("[INFO] SIGTERM received. Shutting down...");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("[INFO] SIGINT received. Shutting down...");
  process.exit(0);
});