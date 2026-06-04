// YAML primary I/O — PSDL's canonical authoring format.
// JSON is a subset of YAML, so parsePsdl also accepts JSON strings.

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { validatePacket } from "./validate.js";
import type { Packet } from "./types.js";

export type ParseResult =
  | { ok: true; packet: Packet }
  | { ok: false; errors: string[] };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/* ------------------------------------------------------------------ *
 * Authoring shorthand normalization (§4):
 *   bare integer N  → { kind: lit, value: N }
 *   bare string "f" → { kind: ref, field: "f" }
 * Applied only in expression slots; "eos"/"auto" sentinels are preserved.
 * ------------------------------------------------------------------ */

function toExpr(v: unknown): unknown {
  if (typeof v === "number") return { kind: "lit", value: v };
  if (typeof v === "string") return { kind: "ref", field: v };
  if (isObj(v)) return normExprObj(v);
  return v;
}

function normExprObj(o: Obj): Obj {
  switch (o.kind) {
    case "op":
      return { ...o, a: toExpr(o.a), b: toExpr(o.b) };
    case "cond":
      return { ...o, test: toExpr(o.test), t: toExpr(o.t), f: toExpr(o.f) };
    case "peek":
      return o.offset !== undefined ? { ...o, offset: toExpr(o.offset) } : o;
    case "lookup":
      return { ...o, key: toExpr(o.key) };
    default:
      return o;
  }
}

function normContainers(list: unknown): unknown {
  if (!Array.isArray(list)) return list;
  return list.map(normContainer);
}

function normContainer(node: unknown): unknown {
  if (!isObj(node)) return node;
  let src: Obj = node;
  // Legacy: { kind: optional, field } → { container }
  if (src.kind === "optional" && "field" in src && !("container" in src)) {
    const { field, ...rest } = src;
    src = { ...rest, container: field };
  }
  const o: Obj = { ...src };
  const kind = o.kind;
  if (kind === undefined || kind === "field") {
    const t = o.type;
    if (isObj(t) && t.kind === "bytes" && t.n !== "auto" && t.n !== undefined)
      o.type = { ...t, n: toExpr(t.n) };
    return o;
  }
  switch (kind) {
    case "virtual":
      o.expr = toExpr(o.expr);
      return o;
    case "optional":
      if ("when" in o) o.when = toExpr(o.when);
      if ("container" in o) o.container = normContainer(o.container);
      return o;
    case "repeat":
      if (isObj(o.count) && "until" in o.count) o.count = { until: toExpr(o.count.until) };
      else if (o.count !== "eos" && o.count !== undefined) o.count = toExpr(o.count);
      if (isObj(o.element)) o.element = { ...o.element, fields: normContainers(o.element.fields) };
      return o;
    case "switch": {
      if ("on" in o) o.on = toExpr(o.on);
      if (isObj(o.cases)) {
        const cases: Obj = {};
        for (const [k, arm] of Object.entries(o.cases))
          cases[k] = isObj(arm) ? { ...arm, fields: normContainers(arm.fields) } : arm;
        o.cases = cases;
      }
      return o;
    }
    case "bounded":
      if ("bytes" in o) o.bytes = toExpr(o.bytes);
      o.fields = normContainers(o.fields);
      return o;
    case "encrypted":
      if (o.wireBits !== undefined) o.wireBits = toExpr(o.wireBits);
      if (isObj(o.plaintext)) o.plaintext = { ...o.plaintext, fields: normContainers(o.plaintext.fields) };
      return o;
    case "group":
      o.children = normContainers(o.children);
      return o;
    default:
      return o; // align, ref
  }
}

function normalizeShorthands(raw: Obj): Obj {
  const out = { ...raw };
  if (Array.isArray(out.body)) out.body = normContainers(out.body);
  if (isObj(out.defs)) {
    const defs: Obj = {};
    for (const [k, def] of Object.entries(out.defs))
      defs[k] = isObj(def) ? { ...def, fields: normContainers(def.fields) } : def;
    out.defs = defs;
  }
  if (Array.isArray(out.constraints))
    out.constraints = out.constraints.map((c) =>
      isObj(c) ? { ...c, lhs: toExpr(c.lhs), rhs: toExpr(c.rhs) } : c);
  return out;
}

/* ------------------------------------------------------------------ *
 * Parse / stringify
 * ------------------------------------------------------------------ */

export function parsePsdl(source: string): ParseResult {
  let raw: unknown;
  try {
    raw = parseYaml(source);
  } catch (e) {
    return { ok: false, errors: [`YAML parse error: ${String(e)}`] };
  }
  if (!isObj(raw)) {
    return { ok: false, errors: ["PSDL document must be a YAML mapping."] };
  }
  const packet = normalizeShorthands(raw) as unknown as Packet;
  const errors = validatePacket(packet);
  if (errors.length > 0) return { ok: false, errors: errors.map((e) => e.message) };
  return { ok: true, packet };
}

export function stringifyPsdl(packet: Packet): string {
  return stringifyYaml(packet, {
    lineWidth: 0,
    defaultKeyType: "PLAIN",
    defaultStringType: "PLAIN",
  });
}
