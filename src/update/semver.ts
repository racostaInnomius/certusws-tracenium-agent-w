// src/update/semver.ts
//
// Tiny semver helpers shared between update-service and update-task.
//
// Why not use `semver` from npm: it's ~60 KB minified and we need exactly
// two operations — compare + shape validation — on strings we fully
// control (they come from our own backend metadata endpoint). A bundled
// 60 KB of code for two dozen lines of logic is not worth the dep churn.
//
// Prerelease / build-metadata handling is intentionally dumb: "1.0.94-rc1"
// parses to [1, 0, 89, 0] (the `rc1` segment drops to 0). That matches the
// old ad-hoc implementations that were duplicated across both callers;
// the point of extracting is to keep behaviour identical, not to upgrade
// it in place. If we later need strict semver ordering, switch the whole
// fleet in one file rather than hunting duplicates again.

export function compareSemver(a: string, b: string): number {
  const parse = (v: string): number[] =>
    v.split(".").map((x) => {
      const n = Number(x);
      return Number.isFinite(n) ? n : 0;
    });

  const av = parse(a);
  const bv = parse(b);
  const len = Math.max(av.length, bv.length);

  for (let i = 0; i < len; i += 1) {
    const ai = av[i] ?? 0;
    const bi = bv[i] ?? 0;

    if (ai !== bi) {
      return ai > bi ? 1 : -1;
    }
  }

  return 0;
}

export function looksLikeSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?$/.test(v);
}
