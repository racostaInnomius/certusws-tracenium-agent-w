// src/plugins/asp/predicate.ts
//
// ADR-0022 — el lenguaje de predicados de los indicadores de ASP.
//
// ⚠️ ESTE FICHERO EXISTE DOS VECES, A PROPÓSITO.
// El agente evalúa en local (decisión 3: el backend nunca recibe objetos de AD),
// así que la semántica tiene que vivir en el agente. El backend la necesita para
// que el `dry-run` y la carga del catálogo rechacen un predicado que no compila
// ANTES de que viaje a un DC. Los dos repos se despliegan por separado y no
// comparten paquete, así que hay una copia en cada uno:
//
//   certusws-tracenium/modules/asp/predicate.ts
//   certusws-tracenium-agent-w/src/plugins/asp/predicate.ts
//
// y un corpus de casos idéntico en los dos (`predicate-conformance.json`) que
// cada suite ejecuta. Cambiar la semántica en un lado sin copiar el corpus hace
// fallar el test del otro — es la misma disciplina que la tabla de timeouts
// IPC, pineada a mano en ambos repos.
//
// Forma: un subconjunto con los MISMOS nombres de regla que el evaluador de SCP
// cuando la regla es la misma (`equals`, `in_set`, `all_of`, `any_of`,
// `regex_match`…), más las que AD necesita y SCP no (`bits_all`, `at_most`).
// No se reutiliza el intérprete de SCP porque sus veredictos son otros
// (`not_applicable` por ruta ausente, `info`, `error`) y en ASP una ruta
// ausente es `not_assessed`: la evidencia no llegó, no que no aplique.
//
// Nada aquí ejecuta código del catálogo: el predicado es datos, se recorre con
// límites de profundidad y de nodos, y las regex tienen tope de longitud.

export type Predicate = { rule: string; [key: string]: unknown };

export type PredicateOutcome =
  | { outcome: "true" }
  | { outcome: "false" }
  | { outcome: "missing"; path: string };

const MAX_DEPTH = 5;
const MAX_NODES = 60;
const MAX_REGEX_LENGTH = 200;
const PATH_RE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

type RuleSpec = {
  /** Parámetros obligatorios y su tipo. */
  params: Record<string, "path" | "scalar" | "array" | "number" | "integer" | "string" | "rules" | "rule">;
};

const RULES: Record<string, RuleSpec> = {
  equals: { params: { path: "path", value: "scalar" } },
  not_equals: { params: { path: "path", value: "scalar" } },
  in_set: { params: { path: "path", values: "array" } },
  not_in_set: { params: { path: "path", values: "array" } },
  at_most: { params: { path: "path", max: "number" } },
  at_least: { params: { path: "path", min: "number" } },
  between: { params: { path: "path", min: "number", max: "number" } },
  is_true: { params: { path: "path" } },
  is_false: { params: { path: "path" } },
  regex_match: { params: { path: "path", pattern: "string" } },
  regex_not_match: { params: { path: "path", pattern: "string" } },
  bits_all: { params: { path: "path", mask: "integer" } },
  bits_none: { params: { path: "path", mask: "integer" } },
  all_of: { params: { rules: "rules" } },
  any_of: { params: { rules: "rules" } },
  not: { params: { predicate: "rule" } }
};

export const PREDICATE_RULE_NAMES: readonly string[] = Object.keys(RULES);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

function isScalar(v: unknown): boolean {
  return v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

/**
 * Valida la forma de un predicado. Devuelve la lista de problemas; vacía = compila.
 * No evalúa nada: es lo que usan la carga del catálogo y el `dry-run`.
 */
export function compilePredicate(predicate: unknown): string[] {
  const errors: string[] = [];
  let nodes = 0;

  const walk = (node: unknown, where: string, depth: number): void => {
    nodes += 1;
    if (nodes > MAX_NODES) {
      if (nodes === MAX_NODES + 1) errors.push(`${where}: more than ${MAX_NODES} nodes`);
      return;
    }
    if (depth > MAX_DEPTH) {
      errors.push(`${where}: deeper than ${MAX_DEPTH}`);
      return;
    }
    if (!isPlainObject(node)) {
      errors.push(`${where}: predicate must be an object`);
      return;
    }
    const name = node.rule;
    if (typeof name !== "string" || !Object.prototype.hasOwnProperty.call(RULES, name)) {
      errors.push(`${where}: unknown rule ${JSON.stringify(name)}`);
      return;
    }
    const spec = RULES[name];
    for (const [param, type] of Object.entries(spec.params)) {
      const v = node[param];
      const at = `${where}.${param}`;
      switch (type) {
        case "path":
          if (typeof v !== "string" || !PATH_RE.test(v) || v.split(".").some((s) => FORBIDDEN_SEGMENTS.has(s))) {
            errors.push(`${at}: invalid path`);
          }
          break;
        case "scalar":
          if (!isScalar(v)) errors.push(`${at}: must be a scalar`);
          break;
        case "array":
          if (!Array.isArray(v) || v.length === 0 || !v.every(isScalar)) errors.push(`${at}: must be a non-empty array of scalars`);
          break;
        case "number":
          if (typeof v !== "number" || !Number.isFinite(v)) errors.push(`${at}: must be a finite number`);
          break;
        case "integer":
          if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) errors.push(`${at}: must be a non-negative integer`);
          break;
        case "string":
          if (typeof v !== "string" || v.length === 0) {
            errors.push(`${at}: must be a non-empty string`);
          } else if (v.length > MAX_REGEX_LENGTH) {
            errors.push(`${at}: longer than ${MAX_REGEX_LENGTH}`);
          } else {
            try {
              new RegExp(v, typeof node.flags === "string" && node.flags === "i" ? "i" : "");
            } catch (err: any) {
              errors.push(`${at}: invalid regex (${err?.message || err})`);
            }
          }
          break;
        case "rules":
          if (!Array.isArray(v) || v.length === 0) {
            errors.push(`${at}: must be a non-empty array of predicates`);
          } else {
            v.forEach((child, i) => walk(child, `${at}[${i}]`, depth + 1));
          }
          break;
        case "rule":
          walk(v, at, depth + 1);
          break;
      }
    }
    if (name === "between" && typeof node.min === "number" && typeof node.max === "number" && node.min > node.max) {
      errors.push(`${where}: min greater than max`);
    }
    if (node.flags !== undefined && node.flags !== "i") {
      errors.push(`${where}.flags: only "i" is supported`);
    }
  };

  walk(predicate, "predicate", 0);
  return errors;
}

/** Resuelve una ruta con puntos. `found:false` si falta cualquier segmento. */
export function resolveEvidencePath(root: unknown, path: string): { found: boolean; value: unknown } {
  let node: any = root;
  for (const part of path.split(".")) {
    if (FORBIDDEN_SEGMENTS.has(part)) return { found: false, value: undefined };
    if (node === null || typeof node !== "object") return { found: false, value: undefined };
    if (!Object.prototype.hasOwnProperty.call(node, part)) return { found: false, value: undefined };
    node = node[part];
  }
  // `undefined` explícito cuenta como ausente; `null` es un valor reportado.
  if (node === undefined) return { found: false, value: undefined };
  return { found: true, value: node };
}

function toNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  // Los atributos de AD llegan como texto (`"10"`); una cadena que ENTERA es un
  // número se acepta. `Number("")` vale 0 y un atributo vacío no es cero.
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v.trim());
  return null;
}

class Missing {
  constructor(readonly path: string) {}
}

/**
 * Evalúa un predicado YA compilado contra la evidencia de un indicador.
 *
 * `missing` significa que la evidencia que el predicado necesita no llegó —
 * el indicador sale `not_assessed` con ese motivo, nunca `pass`. Un valor que
 * llegó con el tipo equivocado (texto donde se espera número) es `false`: el
 * colector respondió y la respuesta no cumple.
 */
export function evaluatePredicate(predicate: Predicate, evidence: unknown): PredicateOutcome {
  try {
    return evalNode(predicate, evidence) ? { outcome: "true" } : { outcome: "false" };
  } catch (err) {
    if (err instanceof Missing) return { outcome: "missing", path: err.path };
    throw err;
  }
}

function read(evidence: unknown, path: unknown): unknown {
  const p = String(path);
  const r = resolveEvidencePath(evidence, p);
  if (!r.found) throw new Missing(p);
  return r.value;
}

function evalNode(node: any, evidence: unknown): boolean {
  switch (node.rule) {
    case "equals":
      return read(evidence, node.path) === node.value;
    case "not_equals":
      return read(evidence, node.path) !== node.value;
    case "in_set":
      return (node.values as unknown[]).includes(read(evidence, node.path));
    case "not_in_set":
      return !(node.values as unknown[]).includes(read(evidence, node.path));
    case "at_most": {
      const n = toNumber(read(evidence, node.path));
      return n !== null && n <= node.max;
    }
    case "at_least": {
      const n = toNumber(read(evidence, node.path));
      return n !== null && n >= node.min;
    }
    case "between": {
      const n = toNumber(read(evidence, node.path));
      return n !== null && n >= node.min && n <= node.max;
    }
    case "is_true":
      return read(evidence, node.path) === true;
    case "is_false":
      return read(evidence, node.path) === false;
    case "regex_match":
    case "regex_not_match": {
      const v = read(evidence, node.path);
      const s = v === null ? "" : String(v);
      const matched = new RegExp(node.pattern, node.flags === "i" ? "i" : "").test(s);
      return node.rule === "regex_match" ? matched : !matched;
    }
    case "bits_all":
    case "bits_none": {
      const n = toNumber(read(evidence, node.path));
      if (n === null || !Number.isSafeInteger(n)) return false;
      // Aritmética de 32 bits sin signo: userAccountControl cabe y `&` de JS
      // opera en 32 bits con signo.
      const masked = (n & node.mask) >>> 0;
      return node.rule === "bits_all" ? masked === node.mask >>> 0 : masked === 0;
    }
    case "all_of":
      // ⚠️ Una rama ausente hace `missing` al conjunto aunque otra ya sea falsa:
      // afirmar un `fail` sobre evidencia incompleta es igual de falso que un pass.
      return (node.rules as any[]).map((r) => evalNode(r, evidence)).every(Boolean);
    case "any_of": {
      let missing: Missing | null = null;
      for (const r of node.rules as any[]) {
        try {
          if (evalNode(r, evidence)) return true;
        } catch (err) {
          if (err instanceof Missing) missing = missing ?? err;
          else throw err;
        }
      }
      if (missing) throw missing;
      return false;
    }
    case "not":
      return !evalNode(node.predicate, evidence);
    default:
      // compilePredicate lo impide; si llega aquí es un predicado sin compilar.
      throw new Error(`asp predicate: unknown rule ${String(node.rule)}`);
  }
}
