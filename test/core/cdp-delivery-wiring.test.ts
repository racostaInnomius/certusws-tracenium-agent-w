// test/core/cdp-delivery-wiring.test.ts
//
// Los dos sitios que encolan un namespace CDP —el planificador y el snapshot
// pedido por el control plane— tienen que asociar el paquete de la línea
// base al id del outbox. Si uno lo olvida, sus envíos nunca mueven la base
// y cada escaneo reenvía lo mismo: no se pierde nada, pero no se ve en
// ningún test de comportamiento. Comprobación de la forma del llamador.

import fs from "node:fs";
import path from "node:path";
import { describe, it, expect } from "vitest";

const read = (rel: string) => fs.readFileSync(path.resolve(__dirname, "../..", rel), "utf8");

describe("quien encola CDP asocia el paquete de la línea base", () => {
  it("⭐ el planificador (tick de CDP)", () => {
    const src = read("src/core/scheduler.ts");
    const start = src.indexOf('ctx.plugins.run("cdp.collect")');
    const block = src.slice(start, src.indexOf('logger.info("FACTS_SNAPSHOT enqueued"', start));
    expect(block).toMatch(/const outboxId = outbox\.enqueue\(\{[\s\S]*?\}\);\s*\n[\s\S]{0,200}stageAttachedCdpDelivery\(namespaces\.cdp, outboxId\);/);
  });

  it("⭐ el snapshot pedido por el control plane (job facts_snapshot)", () => {
    const src = read("src/transport/grpc-stream.ts");
    const start = src.indexOf("const facts = await buildDeviceFacts(ctx, namespaces);");
    const block = src.slice(start, src.indexOf('"FACTS_SNAPSHOT enqueued from control message"', start));
    expect(block).toMatch(/const outboxId = outbox\.enqueue\(\{[\s\S]*?\}\);\s*\n[\s\S]{0,200}stageAttachedCdpDelivery\(namespaces\.cdp, outboxId\);/);
  });

  it("y nadie vuelve a escribir la base al recoger", () => {
    const src = read("src/plugins/cdp/index.ts");
    expect(src).not.toMatch(/commitCdpBaseline\(/);
    expect(src).not.toMatch(/writeCdpMeta\(/);
  });
});
