// privsvc/linux/src/cdp-acme-http01.ts
//
// ADR-0033 F2b — `cdp.acme.http01`. La regla y la escritura viven en
// privsvc/shared/acme-http01.ts (común a macOS y Linux); aquí sólo van las
// raíces de esta plataforma y dónde pone el administrador las suyas.

import path from "path";
import { handleHttp01, LINUX_DEFAULT_ROOTS } from "../../shared/acme-http01";
import { CONFIG_DIR } from "./paths";
import { fail, success, type PrivSvcRequest, type PrivSvcResponse } from "./protocol";
import { logger } from "./logger";

export function handleCdpAcmeHttp01(req: PrivSvcRequest): PrivSvcResponse {
  const out = handleHttp01(req.params || {}, { roots: LINUX_DEFAULT_ROOTS, extraRootsFile: path.join(CONFIG_DIR, "acme-webroots") });
  if (!out.ok) {
    logger.warn("cdp_acme_http01_failed", { code: out.code, message: out.message });
    return fail(req.id, out.code, out.message);
  }
  logger.info("cdp_acme_http01", { action: (req.params as any)?.action, path: out.result.path });
  return success(req.id, out.result);
}
