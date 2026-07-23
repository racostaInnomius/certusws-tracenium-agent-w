// Live smoke — runs the REAL CDP macOS + Java collectors on this machine.
// Not shipped; run with:
//   npx esbuild experiments/cdp-live-smoke.ts --bundle --platform=node \
//     --external:better-sqlite3 --outfile=/tmp/cdp-live-smoke.cjs && node /tmp/cdp-live-smoke.cjs
import os from "os";
import { collectMacosCdp } from "../src/plugins/cdp/providers/macos";
import { collectLinuxCdp } from "../src/plugins/cdp/providers/linux";
import { collectJavaStores } from "../src/plugins/cdp/providers/java-stores";

const ctx: any = {
  policyRuntime: { getCdpJavaKeystorePaths: () => [] },
  logger: { warn: console.warn, info: () => {}, debug: () => {} }
};

(async () => {
  const platform = os.platform();
  const mac =
    platform === "darwin" ? await collectMacosCdp()
    : platform === "linux" ? await collectLinuxCdp()
    : { items: [], stores: [], parseFailures: 0 };
  console.log(`== OS stores (${platform}) ==`);
  console.log("stores:", mac.stores.map((s) => `${s.id} (${s.scope})`));
  console.log("items:", mac.items.length, "parseFailures:", mac.parseFailures);
  console.log("withPrivateKey:", mac.items.filter((i) => i.hasPrivateKey).length);
  const sample = mac.items.find((i) => i.store.scope === "machine") ?? mac.items[0];
  if (sample) {
    console.log("sample:", JSON.stringify({
      subjectCN: sample.subjectCN, issuerCN: sample.issuerCN, notAfter: sample.notAfter,
      keyAlgorithm: sample.keyAlgorithm, keySizeBits: sample.keySizeBits,
      sigAlg: sample.signatureAlgorithm, hasPrivateKey: sample.hasPrivateKey
    }));
  }

  const java = await collectJavaStores(ctx);
  console.log("== Java stores ==");
  console.log("stores:", java.stores.map((s) => s.name));
  console.log("items:", java.items.length, "parseFailures:", java.parseFailures);
  console.log("storeErrors:", java.storeErrors);
  const perStore: Record<string, number> = {};
  for (const i of java.items) perStore[i.store.name] = (perStore[i.store.name] ?? 0) + 1;
  console.log("certs per store:", perStore);
})();
