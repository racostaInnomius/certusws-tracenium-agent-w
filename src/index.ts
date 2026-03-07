// src/index.ts
import { startService } from "./core/service";

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