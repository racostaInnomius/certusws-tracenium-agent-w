// test/privsvc/sysctl.test.ts
//
// Unit coverage for the sysctl (kernel/network hardening) evidence helpers: value
// coercion + dotted-key → nested-tree materialisation (so the backend evaluator
// can resolve `sysctl.net.ipv4.conf.all.rp_filter`).

import { describe, it, expect } from "vitest";
import { coerceSysctlValue, buildSysctlTree, SYSCTL_KEYS } from "../../privsvc/linux/src/sysctl";

describe("coerceSysctlValue", () => {
  it("coerces a pure integer (trimming the trailing newline) to a number", () => {
    expect(coerceSysctlValue("1\n")).toBe(1);
    expect(coerceSysctlValue("0")).toBe(0);
    expect(coerceSysctlValue("-1\n")).toBe(-1);
  });

  it("keeps a non-integer value as a trimmed string", () => {
    expect(coerceSysctlValue("0 0 0\n")).toBe("0 0 0");
    expect(coerceSysctlValue("  something ")).toBe("something");
  });
});

describe("buildSysctlTree", () => {
  it("materialises dotted keys into a nested tree the evaluator can walk", () => {
    const tree = buildSysctlTree([
      { key: "net.ipv4.conf.all.rp_filter", value: 1 },
      { key: "net.ipv4.tcp_syncookies", value: 1 },
      { key: "kernel.randomize_va_space", value: 2 },
    ]);
    expect(tree).toEqual({
      net: { ipv4: { conf: { all: { rp_filter: 1 } }, tcp_syncookies: 1 } },
      kernel: { randomize_va_space: 2 },
    });
  });

  it("OMITS keys whose value is null/undefined (→ not_applicable downstream)", () => {
    const tree = buildSysctlTree([
      { key: "net.ipv4.tcp_syncookies", value: 1 },
      { key: "net.ipv4.conf.all.rp_filter", value: null },
      { key: "kernel.randomize_va_space", value: undefined },
    ]);
    expect(tree).toEqual({ net: { ipv4: { tcp_syncookies: 1 } } });
    expect(tree.kernel).toBeUndefined();
  });

  it("ignores prototype-polluting segments defensively", () => {
    const tree = buildSysctlTree([{ key: "net.__proto__.polluted", value: 1 }]);
    expect(({} as any).polluted).toBeUndefined();
    expect(tree).toEqual({});
  });

  it("exposes a curated, environment-safe key set (no ip_forward)", () => {
    expect(SYSCTL_KEYS).toContain("net.ipv4.conf.all.rp_filter");
    expect(SYSCTL_KEYS).toContain("kernel.randomize_va_space");
    expect(SYSCTL_KEYS).not.toContain("net.ipv4.ip_forward");
  });
});
