import type { IPrivSvcClient } from "../core/agent-context";

export function createPrivSvcClient(): IPrivSvcClient {
  switch (process.platform) {
    case "win32": {
      const { PrivSvcClient } = require("./privsvc-client-windows") as typeof import("./privsvc-client-windows");
      return new PrivSvcClient();
    }

    case "darwin": {
      const { PrivSvcClient } = require("./privsvc-client-macos") as typeof import("./privsvc-client-macos");
      return new PrivSvcClient();
    }

    case "linux": {
      const { PrivSvcClient } = require("./privsvc-client-linux") as typeof import("./privsvc-client-linux");
      return new PrivSvcClient();
    }

    default:
      throw new Error(`Unsupported platform for PrivSvcClient: ${process.platform}`);
  }
}
