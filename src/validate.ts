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
const DECIMAL_INT_RE = /^(0|[1-9][0-9]*)$/;
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
      // §4/§11.1: every lookup key and value must be a non-negative decimal
      // integer. Keys arrive as object-key strings; values must be integers.
      for (const [k, v] of Object.entries(l.table as Record<string, unknown>)) {
        if (!DECIMAL_INT_RE.test(k)) return false;
        if (typeof v !== "number" || !Number.isInteger(v) || v < 0) return false;
      }
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

/**
 * Scope-provider and document-order context (§4, §10.1, §11.1). Threaded
 * through the container walk so expression placement can detect:
 *  - `remaining`/`enclosingBits` outside a budgeted scope provider, and
 *  - `wireSize`/repeat-id `ref` forward references (target after / still open).
 */
type PlacementCtx = {
  /** `remaining` resolvable here (innermost provider carries a byte budget). */
  remainingOk: boolean;
  /** `enclosingBits` resolvable here (innermost provider carries a bit budget). */
  enclosingBitsOk: boolean;
  /** Ids fully declared and closed before this point, in document order. */
  declaredIds: Set<string>;
  /** Container ids currently open on the parse stack (not yet closed). */
  openIds: Set<string>;
  /** All repeat container ids anywhere in the document. */
  repeatIds: Set<string>;
};

function validateExprPlacement(
  expr: Expr,
  slot: ExprSlot,
  ctx: string,
  errors: ValidationError[],
  pc?: PlacementCtx,
): void {
  walkExpr(expr, (e) => {
    if (e.kind === "peek" && !PEEK_ALLOWED.has(slot))
      errors.push({ message: `${ctx}: peek may not appear in ${slot} (allowed: switch.on, optional.when, repeat.count/until).` });
    if (e.kind === "enclosingField" && slot !== "constraint")
      errors.push({ message: `${ctx}: enclosingField may only appear in constraints, not ${slot}.` });
    if (e.kind === "prevIter" && slot !== "repeat.count" && slot !== "repeat.until")
      errors.push({ message: `${ctx}: prevIter may only appear in repeat.count or repeat.until, not ${slot}.` });
    if (pc === undefined) return;
    // §11.1: remaining/enclosingBits scope-provider placement. Constraints are
    // evaluated over the fully-parsed env, not at a body position, so they are
    // exempt from the scope-provider restriction.
    if (slot !== "constraint") {
      if (e.kind === "remaining" && !pc.remainingOk)
        errors.push({ message: `${ctx}: 'remaining' used outside a scope-providing container with a defined byte budget (§11.1).` });
      if (e.kind === "enclosingBits" && !pc.enclosingBitsOk)
        errors.push({ message: `${ctx}: 'enclosingBits' used outside a scope-providing container that carries an injected bit budget (§11.1).` });
      // §10.1/§11.1: forward-reference rules for wireSize and repeat-id ref.
      if (e.kind === "wireSize") {
        if (pc.openIds.has(e.target))
          errors.push({ message: `${ctx}: wireSize target "${e.target}" is an enclosing/not-yet-closed container (§11.1).` });
        else if (!pc.declaredIds.has(e.target))
          errors.push({ message: `${ctx}: wireSize target "${e.target}" does not precede this expression in document order (§11.1).` });
      }
      if (e.kind === "ref" && pc.repeatIds.has(e.field) && !pc.declaredIds.has(e.field))
        errors.push({ message: `${ctx}: ref to repeat container id "${e.field}" precedes that repeat in document order (§11.1).` });
    }
  });
}

/* ------------------------------------------------------------------ *
 * Types
 * ------------------------------------------------------------------ */

function validateType(type: Type, ctx: string, errors: ValidationError[], pc?: PlacementCtx): void {
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
      if (!isValidExpr(type.n))
        errors.push({ message: `${ctx}: bytes has a malformed length expression.` });
      else
        validateExprPlacement(type.n, "bytes.n", ctx, errors, pc);
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
  /** Scope/document-order context for §11.1 placement checks (undefined in defs). */
  pc?: PlacementCtx;
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
  validateType(field.type, `${ctx}/${field.id}`, w.errors, w.pc);
  if (field.byteOrder !== undefined && field.byteOrder !== "BE" && field.byteOrder !== "LE")
    w.errors.push({ message: `${ctx}/${field.id}: byteOrder must be 'BE' or 'LE'.` });
  if (field.computedFrom !== undefined) {
    if (field.computedFrom.kind !== "wireSize")
      w.errors.push({ message: `${ctx}/${field.id}: computedFrom must be a wireSize expression.` });
    else
      validateExprPlacement(field.computedFrom, "computedFrom", `${ctx}/${field.id}`, w.errors, w.pc);
  }
}

/** Run `body` with `id` marked open on the parse stack (§10.1 wireSize rule). */
function withOpen(w: WalkCtx, id: string | undefined, body: () => void): void {
  if (w.pc === undefined || id === undefined) { body(); return; }
  const added = !w.pc.openIds.has(id);
  if (added) w.pc.openIds.add(id);
  try { body(); } finally { if (added) w.pc.openIds.delete(id); }
}

function validateGroup(g: Group, ctx: string, w: WalkCtx): void {
  if (!Array.isArray(g.children))
    w.errors.push({ message: `${ctx}: group "${g.id}" must have a children array.` });
  else withOpen(w, g.id, () => {
    for (const child of g.children) validateContainerCtx(child, `${ctx}/${g.id}`, w);
  });
}

function validateRepeat(r: Repeat, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${r.id}`;
  if (r.count === "eos") {
    /* ok */
  } else if (typeof r.count === "object" && "until" in r.count) {
    if (!isValidExpr(r.count.until)) w.errors.push({ message: `${sub}: repeat until has a malformed expression.` });
    else validateExprPlacement(r.count.until, "repeat.until", sub, w.errors, w.pc);
  } else if (!isValidExpr(r.count)) {
    w.errors.push({ message: `${sub}: repeat count has a malformed expression.` });
  } else {
    validateExprPlacement(r.count, "repeat.count", sub, w.errors, w.pc);
  }
  if (!r.element || !Array.isArray(r.element.fields))
    w.errors.push({ message: `${sub}: repeat is missing an element struct.` });
  else withOpen(w, r.id, () => validateStruct(r.element, sub, w));
}

function validateSwitch(s: Switch, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${s.id}`;
  if (!isValidExpr(s.on)) w.errors.push({ message: `${sub}: switch has an invalid discriminator expression.` });
  else validateExprPlacement(s.on, "switch.on", sub, w.errors, w.pc);
  if (!s.cases || typeof s.cases !== "object") {
    w.errors.push({ message: `${sub}: switch is missing cases.` });
    return;
  }
  withOpen(w, s.id, () => {
    for (const [key, struct] of Object.entries(s.cases)) {
      if (!SWITCH_KEY_RE.test(key)) {
        w.errors.push({ message: `${sub}: invalid switch case key "${key}" (use decimal, "lo-hi", "a,b,c", or "_").` });
      } else {
        const range = /^(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$/.exec(key);
        if (range && Number(range[1]) > Number(range[2]))
          w.errors.push({ message: `${sub}: invalid range switch case key "${key}" (lo must be <= hi).` });
      }
      validateStruct(struct, `${sub}/${key}`, w);
    }
  });
}

function validateEncrypted(e: Encrypted, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${e.id}`;
  if (!e.plaintext || !Array.isArray(e.plaintext.fields))
    w.errors.push({ message: `${sub}: encrypted container must have a plaintext struct.` });
  if (e.wireBits !== undefined) {
    if (!isValidExpr(e.wireBits)) w.errors.push({ message: `${sub}: encrypted wireBits is malformed.` });
    else validateExprPlacement(e.wireBits, "wireBits", sub, w.errors, w.pc);
  }
  if (!e.plaintext) return;
  // §5/§11.1: an encrypted.plaintext with wireBits provides a bit budget; one
  // without wireBits has no defined budget, so remaining/enclosingBits inside
  // it are validation errors (regardless of any outer top-body budget).
  const prevPc = w.pc;
  if (prevPc !== undefined) {
    const ok = e.wireBits !== undefined;
    w.pc = { ...prevPc, remainingOk: ok, enclosingBitsOk: ok };
  }
  try {
    withOpen(w, e.id, () => validateStruct(e.plaintext, sub, w));
  } finally {
    if (prevPc !== undefined) w.pc = prevPc;
  }
}

function validateBounded(b: Bounded, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${b.id}`;
  if (!isValidExpr(b.bytes)) w.errors.push({ message: `${sub}: bounded bytes is malformed.` });
  else validateExprPlacement(b.bytes, "bounded.bytes", sub, w.errors, w.pc);
  if (!Array.isArray(b.fields)) { w.errors.push({ message: `${sub}: bounded must have a fields array.` }); return; }
  // A `bounded` scope carries a byte budget, so `remaining` is well-defined
  // inside it (§4). `enclosingBits` resolves to the nearest bit-budget provider,
  // which the enclosing context already tracks.
  const prevPc = w.pc;
  if (prevPc !== undefined) w.pc = { ...prevPc, remainingOk: true };
  try {
    withOpen(w, b.id, () => {
      for (const child of b.fields) validateContainerCtx(child, sub, w);
    });
  } finally {
    if (prevPc !== undefined) w.pc = prevPc;
  }
}

function validateOptional(o: Optional, ctx: string, w: WalkCtx): void {
  if (!isValidExpr(o.when)) w.errors.push({ message: `${ctx}: optional has an invalid 'when' expression.` });
  else validateExprPlacement(o.when, "optional.when", ctx, w.errors, w.pc);
  validateContainerCtx(o.container, ctx, w);
}

export function validateContainer(c: Container, ctx: string): void {
  const w: WalkCtx = { errors: [], defs: {}, inDef: false };
  validateContainerCtx(c, ctx, w);
  if (w.errors.length > 0) throw new Error(w.errors[0]!.message);
}

/** The declarable id of a container, if any (used for document-order tracking). */
function containerId(c: Container): string | undefined {
  if (isField(c)) return c.id;
  switch (c.kind) {
    case "group": case "repeat": case "switch":
    case "encrypted": case "bounded": case "ref": case "virtual":
      return c.id;
    case "optional": case "align":
      return c.id;
  }
}

function validateContainerCtx(c: Container, ctx: string, w: WalkCtx): void {
  dispatchContainer(c, ctx, w);
  // §10.1: register this container's id as declared/closed in document order so
  // later siblings' wireSize/repeat-id references resolve, but not earlier ones.
  if (w.pc) {
    const id = containerId(c);
    if (typeof id === "string") w.pc.declaredIds.add(id);
  }
}

function dispatchContainer(c: Container, ctx: string, w: WalkCtx): void {
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
      else validateExprPlacement(c.expr, "virtual.expr", ctx, w.errors, w.pc);
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

/** All repeat container ids reachable in `fields` (§10.1 repeat-id ref rule). */
function collectRepeatIds(fields: Container[], out: Set<string>): void {
  for (const c of fields) {
    if (isField(c)) continue;
    switch (c.kind) {
      case "repeat": out.add(c.id); collectRepeatIds(c.element.fields, out); break;
      case "group": collectRepeatIds(c.children, out); break;
      case "bounded": collectRepeatIds(c.fields, out); break;
      case "optional": collectRepeatIds([c.container], out); break;
      case "encrypted": collectRepeatIds(c.plaintext.fields, out); break;
      case "switch": for (const arm of Object.values(c.cases)) collectRepeatIds(arm.fields, out); break;
    }
  }
}

/**
 * Detect circular references through non-recursive defs (§6/§11.1), direct or
 * indirect. SCOPE LIMITATION: this check only follows ref targets that resolve
 * to a local `def` (`defs[t]`). An import-qualified ref target (one containing a
 * `.`, accepted unconditionally in dispatchContainer because imports are not
 * resolved in this module) is NOT followed, so a cycle that passes through an
 * import boundary cannot be detected here. Import resolution is a tool-layer
 * concern; the tool layer that resolves imports MUST re-run cycle detection
 * over the merged def set to complete the §6 check for transitive import edges.
 */
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

  // Body — single shared WalkCtx so document-order tracking (§10.1) spans the
  // whole body. The top-level body is a scope provider that carries both a byte
  // budget (`remaining`) and an injected bit budget (`enclosingBits`), §4.
  const repeatIds = new Set<string>();
  collectRepeatIds(packet.body ?? [], repeatIds);
  const pc: PlacementCtx = {
    remainingOk: true,
    enclosingBitsOk: true,
    declaredIds: new Set<string>(),
    openIds: new Set<string>(),
    repeatIds,
  };
  const bodyW: WalkCtx = { errors, defs, inDef: false, pc };
  for (const c of packet.body ?? []) {
    validateContainerCtx(c, packet.name, bodyW);
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
