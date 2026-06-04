// PSDL semantic validator — walks the Container tree and enforces invariants
// (§11.1) that JSON Schema alone cannot express: id format, expression
// placement, ref-cycle detection, switch case key format, import uniqueness.

import { walkExpr } from "./expr.js";
import { isField } from "./utils.js";
import type {
  Bounded,
  Container,
  Encrypted,
  Expr,
  Field,
  Group,
  NamedStruct,
  Optional,
  Packet,
  Repeat,
  Struct,
  Switch,
  Type,
} from "./types.js";
import { BIN_OPS } from "./types.js";

const ID_RE = /^[a-zA-Z][a-zA-Z0-9_-]*$/;
const SWITCH_KEY_RE = /^(_|(0|[1-9][0-9]*)|(0|[1-9][0-9]*)-(0|[1-9][0-9]*)|(0|[1-9][0-9]*)(,(0|[1-9][0-9]*))+)$/;

/* ------------------------------------------------------------------ *
 * Structural expression well-formedness
 * ------------------------------------------------------------------ */

export function isValidExpr(expr: unknown): expr is Expr {
  if (typeof expr !== "object" || expr === null) return false;
  const e = expr as { kind?: unknown };
  switch (e.kind) {
    case "lit":
      return typeof (expr as { value?: unknown }).value === "number" &&
        Number.isFinite((expr as { value: number }).value);
    case "ref":
    case "prevIter":
    case "enclosingField":
      return typeof (expr as { field?: unknown }).field === "string";
    case "op": {
      const o = expr as { op?: unknown; a?: unknown; b?: unknown };
      return typeof o.op === "string" && (BIN_OPS as readonly string[]).includes(o.op) &&
        isValidExpr(o.a) && isValidExpr(o.b);
    }
    case "cond": {
      const c = expr as { test?: unknown; t?: unknown; f?: unknown };
      return isValidExpr(c.test) && isValidExpr(c.t) && isValidExpr(c.f);
    }
    case "peek": {
      const p = expr as { bits?: unknown; offset?: unknown };
      if (typeof p.bits !== "number" || !Number.isInteger(p.bits) || p.bits < 1 || p.bits > 64) return false;
      return p.offset === undefined || isValidExpr(p.offset);
    }
    case "lookup": {
      const l = expr as { key?: unknown; table?: unknown };
      if (!isValidExpr(l.key)) return false;
      if (typeof l.table !== "object" || l.table === null) return false;
      return true;
    }
    case "wireSize":
      return typeof (expr as { target?: unknown }).target === "string";
    case "remaining":
    case "enclosingBits":
      return true;
    default:
      return false;
  }
}

/* ------------------------------------------------------------------ *
 * Expression placement (§11.1)
 * ------------------------------------------------------------------ */

type ExprSlot =
  | "bytes.n" | "wireBits" | "switch.on" | "optional.when"
  | "repeat.count" | "repeat.until" | "bounded.bytes" | "virtual.expr"
  | "constraint" | "computedFrom";

const PEEK_ALLOWED: ReadonlySet<ExprSlot> = new Set<ExprSlot>([
  "switch.on", "optional.when", "repeat.count", "repeat.until",
]);

function validateExprPlacement(expr: Expr, slot: ExprSlot, ctx: string, errors: ValidationError[]): void {
  walkExpr(expr, (e) => {
    if (e.kind === "peek" && !PEEK_ALLOWED.has(slot))
      errors.push({ message: `${ctx}: peek may not appear in ${slot} (allowed: switch.on, optional.when, repeat.count/until).` });
    if (e.kind === "enclosingField" && slot !== "constraint")
      errors.push({ message: `${ctx}: enclosingField may only appear in constraints, not ${slot}.` });
    if (e.kind === "prevIter" && slot !== "repeat.until")
      errors.push({ message: `${ctx}: prevIter may only appear in repeat.count.until, not ${slot}.` });
  });
}

/* ------------------------------------------------------------------ *
 * Types
 * ------------------------------------------------------------------ */

function validateType(type: Type, ctx: string, errors: ValidationError[]): void {
  switch (type.kind) {
    case "int":
    case "enum":
      if (!Number.isInteger(type.bits) || type.bits <= 0)
        errors.push({ message: `${ctx}: ${type.kind} must have positive integer bits, got ${type.bits}.` });
      return;
    case "bits":
      if (!Number.isInteger(type.n) || type.n <= 0)
        errors.push({ message: `${ctx}: bits must have positive integer n, got ${type.n}.` });
      return;
    case "bytes":
      if (type.n !== "auto" && !isValidExpr(type.n))
        errors.push({ message: `${ctx}: bytes has a malformed length expression.` });
      else if (type.n !== "auto")
        validateExprPlacement(type.n, "bytes.n", ctx, errors);
      return;
    case "varint":
      if (typeof type.encoding !== "string" || type.encoding.length === 0)
        errors.push({ message: `${ctx}: varint encoding must be a non-empty string.` });
      return;
    case "berLength":
      if (type.maxBytes !== undefined && (!Number.isInteger(type.maxBytes) || type.maxBytes < 1 || type.maxBytes > 5))
        errors.push({ message: `${ctx}: berLength maxBytes must be 1–5, got ${type.maxBytes}.` });
      return;
    default:
      errors.push({ message: `${ctx}: unknown type kind "${(type as { kind: string }).kind}".` });
  }
}

/* ------------------------------------------------------------------ *
 * Containers
 * ------------------------------------------------------------------ */

type WalkCtx = {
  errors: ValidationError[];
  defs: Record<string, NamedStruct>;
  inDef: boolean;
};

function validateField(field: Field, ctx: string, w: WalkCtx): void {
  if (typeof field.id !== "string" || !ID_RE.test(field.id))
    w.errors.push({ message: `${ctx}: field id "${String(field.id)}" must match ${ID_RE}.` });
  if (typeof field.name !== "string")
    w.errors.push({ message: `${ctx}: field "${field.id}" is missing a name.` });
  if (!field.type) {
    w.errors.push({ message: `${ctx}: field "${field.id}" is missing a type.` });
    return;
  }
  validateType(field.type, `${ctx}/${field.id}`, w.errors);
  if (field.byteOrder !== undefined && field.byteOrder !== "BE" && field.byteOrder !== "LE")
    w.errors.push({ message: `${ctx}/${field.id}: byteOrder must be 'BE' or 'LE'.` });
  if (field.computedFrom !== undefined) {
    if (field.computedFrom.kind !== "wireSize")
      w.errors.push({ message: `${ctx}/${field.id}: computedFrom must be a wireSize expression.` });
  }
}

function validateGroup(g: Group, ctx: string, w: WalkCtx): void {
  if (!Array.isArray(g.children))
    w.errors.push({ message: `${ctx}: group "${g.id}" must have a children array.` });
  else for (const child of g.children) validateContainerCtx(child, `${ctx}/${g.id}`, w);
}

function validateRepeat(r: Repeat, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${r.id}`;
  if (r.count === "eos") {
    /* ok */
  } else if (typeof r.count === "object" && "until" in r.count) {
    if (!isValidExpr(r.count.until)) w.errors.push({ message: `${sub}: repeat until has a malformed expression.` });
    else validateExprPlacement(r.count.until, "repeat.until", sub, w.errors);
  } else if (!isValidExpr(r.count)) {
    w.errors.push({ message: `${sub}: repeat count has a malformed expression.` });
  } else {
    validateExprPlacement(r.count, "repeat.count", sub, w.errors);
  }
  if (!r.element || !Array.isArray(r.element.fields))
    w.errors.push({ message: `${sub}: repeat is missing an element struct.` });
  else validateStruct(r.element, sub, w);
}

function validateSwitch(s: Switch, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${s.id}`;
  if (!isValidExpr(s.on)) w.errors.push({ message: `${sub}: switch has an invalid discriminator expression.` });
  else validateExprPlacement(s.on, "switch.on", sub, w.errors);
  if (!s.cases || typeof s.cases !== "object") {
    w.errors.push({ message: `${sub}: switch is missing cases.` });
    return;
  }
  for (const [key, struct] of Object.entries(s.cases)) {
    if (!SWITCH_KEY_RE.test(key))
      w.errors.push({ message: `${sub}: invalid switch case key "${key}" (use decimal, "lo-hi", "a,b,c", or "_").` });
    validateStruct(struct, `${sub}/${key}`, w);
  }
}

function validateEncrypted(e: Encrypted, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${e.id}`;
  if (!e.plaintext || !Array.isArray(e.plaintext.fields))
    w.errors.push({ message: `${sub}: encrypted container must have a plaintext struct.` });
  if (e.wireBits !== undefined) {
    if (!isValidExpr(e.wireBits)) w.errors.push({ message: `${sub}: encrypted wireBits is malformed.` });
    else validateExprPlacement(e.wireBits, "wireBits", sub, w.errors);
  }
  if (e.plaintext) validateStruct(e.plaintext, sub, w);
}

function validateBounded(b: Bounded, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${b.id}`;
  if (!isValidExpr(b.bytes)) w.errors.push({ message: `${sub}: bounded bytes is malformed.` });
  else validateExprPlacement(b.bytes, "bounded.bytes", sub, w.errors);
  if (!Array.isArray(b.fields)) w.errors.push({ message: `${sub}: bounded must have a fields array.` });
  else for (const child of b.fields) validateContainerCtx(child, sub, w);
}

function validateOptional(o: Optional, ctx: string, w: WalkCtx): void {
  if (!isValidExpr(o.when)) w.errors.push({ message: `${ctx}: optional has an invalid 'when' expression.` });
  else validateExprPlacement(o.when, "optional.when", ctx, w.errors);
  validateContainerCtx(o.container, ctx, w);
}

export function validateContainer(c: Container, ctx: string): void {
  const w: WalkCtx = { errors: [], defs: {}, inDef: false };
  validateContainerCtx(c, ctx, w);
  if (w.errors.length > 0) throw new Error(w.errors[0]!.message);
}

function validateContainerCtx(c: Container, ctx: string, w: WalkCtx): void {
  if (isField(c)) { validateField(c, ctx, w); return; }
  switch (c.kind) {
    case "group": validateGroup(c, ctx, w); return;
    case "repeat": validateRepeat(c, ctx, w); return;
    case "switch": validateSwitch(c, ctx, w); return;
    case "encrypted": validateEncrypted(c, ctx, w); return;
    case "bounded": validateBounded(c, ctx, w); return;
    case "optional": validateOptional(c, ctx, w); return;
    case "virtual":
      if (typeof c.id !== "string" || !ID_RE.test(c.id))
        w.errors.push({ message: `${ctx}: virtual id "${String(c.id)}" must match ${ID_RE}.` });
      if (w.inDef)
        w.errors.push({ message: `${ctx}: virtual field "${c.id}" is forbidden inside a defs struct.` });
      if (!isValidExpr(c.expr)) w.errors.push({ message: `${ctx}: virtual "${c.id}" has a malformed expr.` });
      else validateExprPlacement(c.expr, "virtual.expr", ctx, w.errors);
      return;
    case "align":
      if (!Number.isInteger(c.to) || c.to < 1 || (c.to & (c.to - 1)) !== 0 || c.to % 8 !== 0)
        w.errors.push({ message: `${ctx}: align 'to' must be a power of 2 and a multiple of 8, got ${c.to}.` });
      if (c.fill !== undefined && (!Number.isInteger(c.fill) || c.fill < 0 || c.fill > 255))
        w.errors.push({ message: `${ctx}: align 'fill' must be 0–255, got ${c.fill}.` });
      return;
    case "ref":
      if (typeof c.ref !== "string" || c.ref.length === 0)
        w.errors.push({ message: `${ctx}: ref container is missing 'ref'.` });
      else if (!w.defs[c.ref] && !c.ref.includes("."))
        w.errors.push({ message: `${ctx}: ref target "${c.ref}" not found in defs.` });
      if (typeof c.id !== "string" || !ID_RE.test(c.id))
        w.errors.push({ message: `${ctx}: ref container id "${String(c.id)}" must match ${ID_RE}.` });
      return;
  }
}

function validateStruct(s: Struct, ctx: string, w: WalkCtx): void {
  if (!Array.isArray(s.fields)) {
    w.errors.push({ message: `${ctx}/${s.id ?? "?"}: struct must have a fields array.` });
    return;
  }
  for (const child of s.fields) validateContainerCtx(child, `${ctx}/${s.id}`, w);
}

/* ------------------------------------------------------------------ *
 * Ref cycle detection (§6, §11.1)
 * ------------------------------------------------------------------ */

function refTargets(fields: Container[], out: string[]): void {
  for (const c of fields) {
    if (isField(c)) continue;
    switch (c.kind) {
      case "ref": out.push(c.ref); break;
      case "group": refTargets(c.children, out); break;
      case "bounded": refTargets(c.fields, out); break;
      case "optional": refTargets([c.container], out); break;
      case "repeat": refTargets(c.element.fields, out); break;
      case "encrypted": refTargets(c.plaintext.fields, out); break;
      case "switch": for (const arm of Object.values(c.cases)) refTargets(arm.fields, out); break;
    }
  }
}

function detectRefCycles(defs: Record<string, NamedStruct>, errors: ValidationError[]): void {
  const visiting = new Set<string>();
  const done = new Set<string>();
  const dfs = (name: string, stack: string[]): void => {
    if (done.has(name)) return;
    const def = defs[name];
    if (!def) return;
    if (def.recursive) return; // recursive defs are allowed to cycle (§6)
    if (visiting.has(name)) {
      errors.push({ message: `defs: circular reference through non-recursive def "${name}" (${[...stack, name].join(" → ")}).` });
      return;
    }
    visiting.add(name);
    const targets: string[] = [];
    refTargets(def.fields, targets);
    for (const t of targets) {
      if (defs[t]) dfs(t, [...stack, name]);
    }
    visiting.delete(name);
    done.add(name);
  };
  for (const name of Object.keys(defs)) dfs(name, []);
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */

export type ValidationError = { message: string };

export function validatePacket(packet: Packet): ValidationError[] {
  const errors: ValidationError[] = [];
  if (typeof packet.name !== "string" || packet.name.length === 0)
    errors.push({ message: "Packet must have a non-empty name." });
  const rowBits = packet.rendererHints?.rowBits ?? packet.rowBits;
  if (rowBits !== undefined && (!Number.isInteger(rowBits) || rowBits <= 0))
    errors.push({ message: `rowBits must be a positive integer, got ${String(rowBits)}.` });
  if (!Array.isArray(packet.body))
    errors.push({ message: "Packet must have a body array." });
  if (packet.byteOrder !== undefined && packet.byteOrder !== "BE" && packet.byteOrder !== "LE")
    errors.push({ message: `byteOrder must be 'BE' or 'LE', got "${String(packet.byteOrder)}".` });
  if (packet.version !== undefined && !/^\d+\.\d+$/.test(packet.version))
    errors.push({ message: `version must be "MAJOR.MINOR", got "${packet.version}".` });

  // Imports: unique `as` prefix, valid format.
  if (packet.imports) {
    const seen = new Set<string>();
    for (const imp of packet.imports) {
      if (typeof imp.source !== "string" || imp.source.length === 0)
        errors.push({ message: `imports: entry is missing a source.` });
      if (typeof imp.as !== "string" || !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(imp.as))
        errors.push({ message: `imports: 'as' prefix "${String(imp.as)}" must match [a-zA-Z][a-zA-Z0-9_]*.` });
      else if (seen.has(imp.as))
        errors.push({ message: `imports: duplicate 'as' prefix "${imp.as}".` });
      else seen.add(imp.as);
    }
  }

  const defs = packet.defs ?? {};
  detectRefCycles(defs, errors);

  // Body
  for (const c of packet.body ?? []) {
    const w: WalkCtx = { errors, defs, inDef: false };
    validateContainerCtx(c, packet.name, w);
  }
  // Defs bodies (virtual forbidden inside)
  for (const [name, def] of Object.entries(defs)) {
    const w: WalkCtx = { errors, defs, inDef: true };
    if (!Array.isArray(def.fields)) {
      errors.push({ message: `defs/${name}: struct must have a fields array.` });
      continue;
    }
    for (const child of def.fields) validateContainerCtx(child, `defs/${name}`, w);
  }
  // Constraints
  for (const [i, con] of (packet.constraints ?? []).entries()) {
    if (!isValidExpr(con.lhs)) errors.push({ message: `constraints[${i}]: malformed lhs.` });
    else validateExprPlacement(con.lhs, "constraint", `constraints[${i}]`, errors);
    if (!isValidExpr(con.rhs)) errors.push({ message: `constraints[${i}]: malformed rhs.` });
    else validateExprPlacement(con.rhs, "constraint", `constraints[${i}]`, errors);
  }
  return errors;
}
