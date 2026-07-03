// vitest.config.ts
//
// Sprint 1 — infraestructura de testing del agente.
//
// Notas de diseño:
// - El repo es CommonJS ("type": "commonjs" + tsconfig module=CommonJS);
//   Vitest transforma los .ts con esbuild, así que no hace falta ts-jest
//   ni cambiar el tsconfig de producción.
// - `better-sqlite3` se usa REAL en los tests del outbox (sobre archivos
//   en tmpdir). Los otros nativos (node-pty, node-datachannel) NO deben
//   cargarse en tests: ningún test de Sprint 1 los importa directamente
//   y los módulos que los arrastran (plugins/rcp, privsvc) se mockean
//   en la frontera (vi.mock) dentro de cada suite.
// - fileParallelism: false — las suites usan vi.useFakeTimers() +
//   process.env compartido y el outbox escribe en disco; serializar
//   archivos evita flakiness sin costo apreciable (3 suites).
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    fileParallelism: false,
    // Los timers fake + streams gRPC simulados no deberían tardar,
    // pero el ciclo completo del circuit breaker avanza ~25 min de
    // reloj fake; damos margen real generoso.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/index.ts"],
      reportsDirectory: "coverage"
    }
  }
});
