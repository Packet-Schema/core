// normalize.ts — walks the Container tree into a flat NormalizedField list.
//
// Implements the §10 processing model: seed phase (§10.2) then a forward,
// single-pass parse that injects context-dependent expression values
// (remaining/enclosingBits/wireSize/prevIter) into the env as it goes.

import { evalExpr, evalExprOr, exprContains, enclosingBitsEnvKey, prevIterEnvKey, remainingEnvKey, wireSizeEnvKey } from "./expr.js";
import { isField } from "./utils.js";
import type {
  Bounded,
  Container,
  Encrypted,
  Expr,
  Field,
  Group,
  NamedStruct,
  Normalized,
  NormalizedField,
  Optional,
  Packet,
  PacketEnv,
  RefContainer,
  Repeat,
  Struct,
  Switch,
  Type,
  ViewMode,
} from "./types.js";

export function berLenEnvKey(fieldId: string): string {
  return `__berLen__${fieldId}`;
}

/** Internal bit-accumulator mirror of wireSizeEnvKey (§4 sub-byte rounding). */
function wireSizeBitsEnvKey(target: string): string {
  return `__wireSizeBits__${target}`;
}

/** Decoder-injected wire bit-width of a varint field (distinct from its value). */
export function varintBitsEnvKey(fieldId: string): string {
  return `__varintBits__${fieldId}`;
}

/** Maximum recursive-def expansion depth (decoder is the real authority, §6). */
const MAX_REF_DEPTH = 64;

export function typeBits(type: Type, env: PacketEnv, fieldId?: string): number {
  switch (type.kind) {
    case "int":
    case "enum":
      return type.bits;
    case "bits":
      return type.n;
    case "bytes":
      return Math.max(0, Math.trunc(evalExprOr(type.n, env))) * 8;
    case "varint":
      // §3/§10: the decoder injects the varint's wire bit-width under a key
      // distinct from the field's value slot (env[fieldId] holds the decoded
      // value, not its width). With no injection the static layout yields 0.
      if (fieldId !== undefined) {
        const v = env.get(varintBitsEnvKey(fieldId));
        if (v !== undefined) return v;
      }
      return 0;
    case "berLength":
      if (fieldId !== undefined) {
        const v = env.get(berLenEnvKey(fieldId));
        if (v !== undefined) return v;
      }
      return 8;
  }
}

/* ------------------------------------------------------------------ *
 * Seeding (§10.2): const wins over defaultValue; recursive.
 * ------------------------------------------------------------------ */

function seedDefaults(
  containers: Container[],
  env: PacketEnv,
  defs: Record<string, NamedStruct>,
  depth = 0,
  activeRecursive: ReadonlySet<string> = new Set(),
): void {
  if (depth > MAX_REF_DEPTH) return;
  for (const c of containers) {
    if (isField(c)) {
      const seed = c.const ?? c.defaultValue;
      if (seed !== undefined && !env.has(c.id)) env.set(c.id, seed);
    } else if (c.kind === "group") {
      seedDefaults(c.children, env, defs, depth, activeRecursive);
    } else if (c.kind === "bounded") {
      seedDefaults(c.fields, env, defs, depth, activeRecursive);
    } else if (c.kind === "encrypted") {
      seedDefaults(c.plaintext.fields, env, defs, depth, activeRecursive);
    } else if (c.kind === "optional") {
      seedDefaults([c.container], env, defs, depth, activeRecursive);
    } else if (c.kind === "repeat") {
      seedDefaults(c.element.fields, env, defs, depth, activeRecursive);
    } else if (c.kind === "switch") {
      for (const arm of Object.values(c.cases)) seedDefaults(arm.fields, env, defs, depth, activeRecursive);
    } else if (c.kind === "ref") {
      const def = defs[c.ref];
      if (!def) continue;
      // §10.2 rule 3: a recursive `ref` (a ref re-entering a def already being
      // seeded) is an unresolved boundary — seed only the directly-declared
      // fields of the def body, not recursively-expanded instances.
      if (activeRecursive.has(c.ref)) continue;
      const nextActive = def.recursive ? new Set([...activeRecursive, c.ref]) : activeRecursive;
      seedDefaults(def.fields, env, defs, depth + 1, nextActive);
    }
    // virtual / align seed nothing
  }
}

/* ------------------------------------------------------------------ *
 * Walk state
 * ------------------------------------------------------------------ */

type EncryptedFrame = {
  parentId: string;
  contextNote: string;
  headerProtected: Set<string>;
};

/**
 * A scope-providing container that carries remaining/enclosingBits (§4).
 * `kind` distinguishes an authored `bounded` budget (over-budget align is a
 * runtime error, §5) from the top-level/decoder-injected end (which caps).
 */
type ScopeFrame = {
  startOffset: number;
  budgetBits?: number;
  kind: "top" | "bounded" | "encrypted";
};

type WalkState = {
  out: NormalizedField[];
  env: PacketEnv;
  offset: number;
  viewMode: ViewMode;
  defs: Record<string, NamedStruct>;
  encryptedStack: EncryptedFrame[];
  scopeStack: ScopeFrame[];
  groupStack: Array<{ id: string; name: string }>;
  repeatIndexStack: number[];
  idPrefix: string;
  refDepth: number;
  /** Selected switch arm key, active for the whole arm subtree (§5). */
  switchCase?: string;
};

/** Inject remaining/enclosingBits for the innermost budgeted scope (§4). */
function injectScopeBudget(state: WalkState): ScopeFrame | undefined {
  let frame: ScopeFrame | undefined;
  for (let i = state.scopeStack.length - 1; i >= 0; i--) {
    const f = state.scopeStack[i]!;
    if (f.budgetBits !== undefined) { frame = f; break; }
  }
  if (frame === undefined) {
    state.env.delete(remainingEnvKey());
    state.env.delete(enclosingBitsEnvKey());
    return undefined;
  }
  // §4 Sub-byte rounding: `remaining` counts whole bytes left in the scope.
  // Compute it from the raw bit gap so it stays consistent when budgetBits is
  // not a whole number of bytes (e.g. an encrypted scope with a sub-byte
  // wireBits): `floor((budget - consumed) / 8)`. This avoids the prior
  // floor(budget/8) - ceil(consumed/8) form, which double-penalised a partial
  // trailing budget byte against a mid-byte cursor and under-reported by one.
  const consumedBits = state.offset - frame.startOffset;
  const remainingBytes = Math.max(0, Math.floor((frame.budgetBits! - consumedBits) / 8));
  state.env.set(remainingEnvKey(), remainingBytes);
  state.env.set(enclosingBitsEnvKey(), frame.budgetBits!);
  return frame;
}

/**
 * §4/§11.2: `remaining`/`enclosingBits` used in a top-level `body` expression
 * when the decoder has not injected the total packet size is a runtime error.
 * The validator already rejects these primitives inside an
 * `encrypted.plaintext` without `wireBits`, and a `bounded` always carries a
 * budget, so the only way to reach an expression referencing them with no
 * budgeted scope frame at runtime is the top-level body with no `totalBits`
 * injected. Distinguish that from "no scope provider at all" and raise, rather
 * than silently resolving to 0.
 */
function guardScopeBudget(state: WalkState, frame: ScopeFrame | undefined, expr: Expr): void {
  if (frame !== undefined) return;
  if (!exprContains(expr, (e) => e.kind === "remaining" || e.kind === "enclosingBits")) return;
  throw new Error(
    "normalize: 'remaining'/'enclosingBits' used at the top-level body but the decoder did not inject the total packet size (pass totalBits) (§4/§11.2).",
  );
}

/**
 * Evaluate an expression with scope budget freshly injected (§4, §10.3).
 *
 * `peek` (§10.6) is NOT injected here: normalize is a static layout pass with
 * no underlying wire buffer, so it cannot read the stream. A `switch.on`,
 * `optional.when`, or `repeat.count` driven by `peek` therefore requires the
 * decoder to pre-seed the corresponding `peekEnvKey(offset, bits)` entry in the
 * env before calling normalize; with no such injection `peek` evaluates to 0
 * (§11.3 "peek reads past available data → 0"), selecting the disc=0 path. This
 * is the documented decoder hand-off for the in-walk evaluation paths.
 *
 * The §10.6 scope-clamp and context-relative current-position semantics (a
 * peek that would read past the innermost scope-providing container's remaining
 * budget yields 0 even if bytes exist beyond the boundary; the current position
 * is the first bit of the switch/optional, the first element for fixed
 * `repeat.count`, or the first bit after the last byte of the just-completed
 * iteration for `repeat.count.until`) CANNOT be enforced here — this package
 * never sees the underlying buffer. The decoder MUST apply that clamp and
 * context-relative origin when seeding each `peekEnvKey(offset, bits)`; the
 * library cannot verify it.
 */
function evalIn(state: WalkState, expr: Expr): number {
  const frame = injectScopeBudget(state);
  // §4/§11.2: top-level `remaining`/`enclosingBits` with no injected total size
  // is a runtime error (not a silent 0).
  guardScopeBudget(state, frame, expr);
  // §11.2 scopes the mid-byte error specifically to sizing a `bytes` field; that
  // guard lives in `emit`. `remaining` in a non-sizing slot (optional.when,
  // switch.on, repeat.count, bounded.bytes) is spec-legal even mid-byte, so no
  // blanket mid-byte throw here.
  return evalExprOr(expr, state.env);
}

function repeatSuffix(state: WalkState): string {
  return state.repeatIndexStack.length > 0 ? `#${state.repeatIndexStack.join("_")}` : "";
}

/** Fully-qualified id for a container/field (prefix + id + repeat suffix). */
function qualify(state: WalkState, id: string): string {
  const prefix = state.idPrefix ? `${state.idPrefix}.` : "";
  return `${prefix}${id}${repeatSuffix(state)}`;
}

/**
 * Record a container/field wire footprint for `wireSize` (§4). Stored under
 * the fully-qualified id (so ref/group/repeat-iteration entries never collide),
 * and additionally accumulated under the unqualified id while inside a repeat
 * so `wireSize(target)` yields the aggregate across iterations.
 *
 * Footprints are tracked in BITS and only floored to a byte count at the point
 * the byte-valued wireSize key is written, so adjacent sub-byte fields (e.g.
 * two nibbles) are not each truncated to 0 bytes (§4 sub-byte rounding).
 *
 * NOTE on duplicate bare ids (§10.1): outside a repeat the unqualified key is
 * overwritten on every occurrence, so when the same id appears more than once
 * in document order (two sibling `ref`s to one def, or a field id reused across
 * switch arms), `wireSize(id)` reflects the LAST occurrence walked before the
 * consuming expression. The validator only approves a `wireSize(target)` whose
 * `target` is already declared/closed and precedes the expression in document
 * order (validate.ts §11.1), so a forward expression resolves the most recent
 * preceding instance. Authors who need a specific instance must give that
 * instance a unique id; a bare id shared by multiple instances resolves to the
 * nearest preceding one, not a sum. (Inside a repeat the bare id deliberately
 * accumulates the per-iteration aggregate, see below.)
 */
function recordWireSize(state: WalkState, id: string, bits: number): void {
  const qid = qualify(state, id);
  state.env.set(wireSizeBitsEnvKey(qid), bits);
  state.env.set(wireSizeEnvKey(qid), Math.floor(bits / 8));
  if (state.repeatIndexStack.length > 0) {
    const prevBits = state.env.get(wireSizeBitsEnvKey(id)) ?? 0;
    const totalBits = prevBits + bits;
    state.env.set(wireSizeBitsEnvKey(id), totalBits);
    state.env.set(wireSizeEnvKey(id), Math.floor(totalBits / 8));
  } else {
    state.env.set(wireSizeBitsEnvKey(id), bits);
    state.env.set(wireSizeEnvKey(id), Math.floor(bits / 8));
  }
}

function emit(state: WalkState, field: Field, path: string): void {
  const frame = injectScopeBudget(state);
  // §4/§11.2: sizing a `bytes` field from `remaining` while the cursor is
  // mid-byte is a runtime error.
  if (field.type.kind === "bytes") {
    const nExpr: Expr = field.type.n;
    // §4/§11.2: top-level `remaining`/`enclosingBits` with no injected total.
    guardScopeBudget(state, frame, nExpr);
    if (state.offset % 8 !== 0 && exprContains(nExpr, (e) => e.kind === "remaining"))
      throw new Error(
        `normalize: 'remaining' sizes bytes field "${field.id}" while the cursor is mid-byte (offset ${state.offset} bits); insert an 'align' first (§11.2).`,
      );
  }
  const bits = typeBits(field.type, state.env, field.id);
  const prefix = state.idPrefix ? `${state.idPrefix}.` : "";
  const suffix = repeatSuffix(state);
  const id = `${prefix}${field.id}${suffix}`;
  const nf: NormalizedField = {
    id,
    name: field.name,
    bits,
    absoluteBitOffset: state.offset,
    originalContainerPath: path,
    ...(field.category !== undefined ? { category: field.category } : {}),
    ...(field.doc !== undefined ? { doc: field.doc } : {}),
    // §5: every field within a selected switch arm carries the arm key, whether
    // a direct child or nested inside a group/optional/bounded/repeat/ref.
    ...(state.switchCase !== undefined ? { switchCase: state.switchCase } : {}),
    ...(state.repeatIndexStack.length > 0 ? { repeatIndex: state.repeatIndexStack[state.repeatIndexStack.length - 1] } : {}),
  };
  if (state.encryptedStack.length > 0) {
    const top = state.encryptedStack[state.encryptedStack.length - 1]!;
    nf.encryptedParentId = top.parentId;
    nf.encryptedContextNote = top.contextNote;
    for (const frame of state.encryptedStack) {
      if (frame.headerProtected.has(field.id)) { nf.headerProtected = true; break; }
    }
  }
  if (field.byteOrder) nf.byteOrder = field.byteOrder;
  if (state.groupStack.length > 0) {
    const top = state.groupStack[state.groupStack.length - 1]!;
    const indexTag = state.repeatIndexStack.length > 0 ? state.repeatIndexStack.join("_") : null;
    nf.groupId = indexTag !== null ? `${top.id}#${indexTag}` : top.id;
    nf.groupName = top.name;
  }
  state.out.push(nf);
  state.env.set(id, state.env.get(id) ?? state.env.get(field.id) ?? field.const ?? field.defaultValue ?? 0);
  state.offset += bits;
  // Record wire footprint for wireSize (parse-direction; §4). Tracked in bits.
  recordWireSize(state, field.id, bits);
}

function walkContainer(c: Container, path: string, state: WalkState): void {
  if (isField(c)) { emit(state, c, path); return; }
  switch (c.kind) {
    case "group": walkGroup(c, path, state); return;
    case "repeat": walkRepeat(c, path, state); return;
    case "switch": walkSwitch(c, path, state); return;
    case "encrypted": walkEncrypted(c, path, state); return;
    case "bounded": walkBounded(c, path, state); return;
    case "align": walkAlign(c, state); return;
    case "virtual": walkVirtual(c, state); return;
    case "optional": {
      const test = evalIn(state, c.when);
      if (test !== 0) walkContainer(c.container, path, state);
      return;
    }
    case "ref": walkRef(c, path, state); return;
  }
}

function walkVirtual(v: { kind: "virtual"; id: string; expr: Expr }, state: WalkState): void {
  const value = evalIn(state, v.expr);
  state.env.set(v.id, value);
  // Zero-width; recorded as a virtual normalized field for tooling.
  state.out.push({
    id: v.id,
    name: v.id,
    bits: 0,
    absoluteBitOffset: state.offset,
    originalContainerPath: `${v.id}`,
    virtual: true,
  });
}

function walkAlign(a: { kind: "align"; to: number }, state: WalkState): void {
  // Round up to next whole byte first, then to the `to` boundary (§5).
  const byteAligned = Math.ceil(state.offset / 8) * 8;
  let target = byteAligned;
  if (a.to > 0) {
    const rem = byteAligned % a.to;
    if (rem !== 0) target = byteAligned + (a.to - rem);
  }
  let padBits = target - state.offset;
  // §5: inside a `bounded` scope, padding exceeding the authored byte budget
  // is a runtime error; at the top-level/decoder-injected end it caps to what
  // remains (SCTP last chunk). NOTE: top-level align capping requires the
  // decoder to inject `totalBits` (which pushes a budgeted top frame). Without
  // an injected total there is no defined end-of-data, so the loop finds no
  // budgeted frame and the align advances unbounded — consistent with
  // `remaining` being undefined at the top level without injection (§4).
  for (let i = state.scopeStack.length - 1; i >= 0; i--) {
    const f = state.scopeStack[i]!;
    if (f.budgetBits !== undefined) {
      const avail = f.budgetBits - (state.offset - f.startOffset);
      if (padBits > avail) {
        if (f.kind === "bounded")
          throw new Error(
            `normalize: align to ${a.to} requires ${padBits} padding bits but only ${Math.max(0, avail)} remain in the bounded scope (§5/§11.2).`,
          );
        padBits = Math.max(0, avail);
      }
      break;
    }
  }
  state.offset += padBits;
}

function walkRef(r: RefContainer, path: string, state: WalkState): void {
  if (state.refDepth >= MAX_REF_DEPTH) return;
  const def = state.defs[r.ref];
  if (!def) return;
  const sub = `${path}/${r.id}`;
  const prevPrefix = state.idPrefix;
  state.idPrefix = state.idPrefix ? `${state.idPrefix}.${r.id}` : r.id;
  state.refDepth++;
  const startOffset = state.offset;
  for (const child of def.fields) walkContainer(child, sub, state);
  // wireSize is keyed by the qualified id from the parent scope, so restore
  // the prefix before recording (the ref id lives in the enclosing scope).
  state.idPrefix = prevPrefix;
  recordWireSize(state, r.id, state.offset - startOffset);
  state.refDepth--;
}

function walkGroup(g: Group, path: string, state: WalkState): void {
  const sub = `${path}/${g.id}`;
  const prev = state.groupStack;
  state.groupStack = [...prev, { id: g.id, name: g.name ?? g.id }];
  const startOffset = state.offset;
  for (const child of g.children) walkContainer(child, sub, state);
  recordWireSize(state, g.id, state.offset - startOffset);
  state.groupStack = prev;
}

function walkBounded(b: Bounded, path: string, state: WalkState): void {
  const sub = `${path}/${b.id}`;
  const budgetBits = Math.max(0, Math.trunc(evalIn(state, b.bytes))) * 8;
  const startOffset = state.offset;
  state.scopeStack.push({ startOffset, budgetBits, kind: "bounded" });
  for (const child of b.fields) walkContainer(child, sub, state);
  state.scopeStack.pop();
  // §5: over-consuming an authored `bounded` budget is a runtime error (mirrors
  // the over-budget `align` rule); under-consumption advances to the scope end.
  const consumed = state.offset - startOffset;
  if (consumed > budgetBits)
    throw new Error(
      `normalize: bounded scope "${b.id}" over-consumed: children used ${consumed} bits but the budget is ${budgetBits} bits (§5/§11.2).`,
    );
  if (consumed < budgetBits) state.offset = startOffset + budgetBits;
  recordWireSize(state, b.id, state.offset - startOffset);
}

function walkRepeat(r: Repeat, path: string, state: WalkState): void {
  const sub = `${path}/${r.id}`;
  const count = resolveRepeatCount(r, state);
  const startOffset = state.offset;
  const prevStack = state.repeatIndexStack;
  const prefix = state.idPrefix ? `${state.idPrefix}.` : "";

  // Element fields whose value participates in prevIter injection (§10.4).
  // Collect ALL leaf field ids reachable in the element — including fields
  // nested inside a group/switch/ref/optional — not just the direct children,
  // so a `repeat.until`/`prevIter` referencing a grouped field still resolves
  // (§10.4). Each descriptor carries the ref-prefix path it is emitted under
  // (groups/switch/optional/bounded do not extend the id prefix; only `ref`
  // does), so the injection probe matches the actually-emitted id.
  const elementFields = collectElementFields(r.element.fields, state.defs);

  // Snapshot prevIter keys so the repeat does not leak stale previous-iteration
  // values into sibling/enclosing containers (§4, §10.4).
  const savedPrevIter = new Map<string, number | undefined>();
  for (const child of elementFields)
    savedPrevIter.set(prevIterEnvKey(child.id), state.env.get(prevIterEnvKey(child.id)));

  // Reset per-target wireSize accumulators so a fresh aggregate is built (§4).
  // Clear ALL container ids reachable in the element — not just the direct
  // fields — so a nested group/switch/ref inside the element does not leak its
  // aggregate from a prior sibling repeat that shares the same id.
  const aggregateIds = collectAggregateIds(r.element.fields);
  for (const aid of aggregateIds) {
    state.env.delete(wireSizeEnvKey(aid));
    state.env.delete(wireSizeBitsEnvKey(aid));
  }

  // §4/§10.2: first iteration sees each field's seeded value (const ?? default).
  for (const child of elementFields) {
    const seed = child.const ?? child.defaultValue;
    if (seed !== undefined) state.env.set(prevIterEnvKey(child.id), seed);
    else state.env.delete(prevIterEnvKey(child.id));
  }

  for (let i = 0; i < count; i++) {
    state.repeatIndexStack = [...prevStack, i];
    const innerPath = `${sub}[${i}]`;
    // Inject prevIter values from the just-completed iteration (§10.4). The
    // emitted id is fully qualified (prefix + id + repeat suffix), so probe the
    // same form — otherwise prevIter never resolves inside a ref expansion.
    if (i > 0) {
      const prevSuffix = `#${[...prevStack, i - 1].join("_")}`;
      for (const child of elementFields) {
        const childPrefix = child.prefixPath ? `${child.prefixPath}.` : "";
        const prevId = `${prefix}${childPrefix}${child.id}${prevSuffix}`;
        const v = state.env.get(prevId);
        if (v !== undefined) state.env.set(prevIterEnvKey(child.id), v);
      }
    }
    for (const child of r.element.fields) walkContainer(child, innerPath, state);
  }
  state.repeatIndexStack = prevStack;

  // Restore prevIter keys so later expressions do not read leftover values.
  for (const [key, value] of savedPrevIter) {
    if (value === undefined) state.env.delete(key);
    else state.env.set(key, value);
  }

  // §10.7: populate env[repeat.id] with the completed iteration count so a
  // `ref` to the repeat id resolves uniformly for fixed/until/eos forms.
  state.env.set(qualify(state, r.id), count);
  state.env.set(r.id, count);
  recordWireSize(state, r.id, state.offset - startOffset);
}

/**
 * Collect every container/field id reachable in `fields` whose wire footprint
 * `recordWireSize` accumulates under its unqualified id (§4). Used to clear
 * stale aggregates at the start of a repeat so sibling repeats sharing an id do
 * not double-count.
 */
/** A leaf field reachable in a repeat element, for prevIter seeding (§10.4). */
type ElementFieldRef = {
  id: string;
  /** Ref-id prefix path the field is emitted under ("" for direct/grouped). */
  prefixPath: string;
  const?: number;
  defaultValue?: number;
};

/**
 * Collect every leaf field reachable in a repeat element — recursing into
 * group/switch/ref/optional/bounded containers — so prevIter seeding and
 * injection cover nested fields, not only direct children (§10.4). Only `ref`
 * extends the emitted id prefix; other containers leave it unchanged.
 */
function collectElementFields(
  fields: Container[],
  defs: Record<string, NamedStruct>,
  prefixPath = "",
  out: ElementFieldRef[] = [],
  seenRefs: ReadonlySet<string> = new Set(),
): ElementFieldRef[] {
  for (const c of fields) {
    if (isField(c)) {
      out.push({ id: c.id, prefixPath, ...(c.const !== undefined ? { const: c.const } : {}), ...(c.defaultValue !== undefined ? { defaultValue: c.defaultValue } : {}) });
      continue;
    }
    switch (c.kind) {
      case "group": collectElementFields(c.children, defs, prefixPath, out, seenRefs); break;
      case "bounded": collectElementFields(c.fields, defs, prefixPath, out, seenRefs); break;
      case "optional": collectElementFields([c.container], defs, prefixPath, out, seenRefs); break;
      case "repeat": /* inner repeat fields belong to that repeat's iterations */ break;
      case "encrypted": collectElementFields(c.plaintext.fields, defs, prefixPath, out, seenRefs); break;
      case "switch": for (const arm of Object.values(c.cases)) collectElementFields(arm.fields, defs, prefixPath, out, seenRefs); break;
      case "ref": {
        if (seenRefs.has(c.ref)) break; // guard against recursive defs
        const def = defs[c.ref];
        if (!def) break;
        const nextPrefix = prefixPath ? `${prefixPath}.${c.id}` : c.id;
        collectElementFields(def.fields, defs, nextPrefix, out, new Set([...seenRefs, c.ref]));
        break;
      }
      // align/virtual contribute no prevIter source
    }
  }
  return out;
}

function collectAggregateIds(fields: Container[], out: string[] = []): string[] {
  for (const c of fields) {
    if (isField(c)) { out.push(c.id); continue; }
    switch (c.kind) {
      case "group": out.push(c.id); collectAggregateIds(c.children, out); break;
      case "bounded": out.push(c.id); collectAggregateIds(c.fields, out); break;
      case "switch": out.push(c.id); for (const arm of Object.values(c.cases)) collectAggregateIds(arm.fields, out); break;
      case "repeat": out.push(c.id); collectAggregateIds(c.element.fields, out); break;
      case "encrypted": out.push(c.id); collectAggregateIds(c.plaintext.fields, out); break;
      case "ref": out.push(c.id); break;
      case "optional": collectAggregateIds([c.container], out); break;
      // align/virtual record no wireSize footprint
    }
  }
  return out;
}

function resolveRepeatCount(r: Repeat, state: WalkState): number {
  // §10.7: the decoder injects the completed iteration count at the repeat's
  // id. When the repeat lives inside a ref expansion or an outer repeat, each
  // runtime instance has a distinct qualified id (prefix + id + repeat suffix),
  // so prefer the per-instance qualified key before falling back to the bare
  // id — otherwise sibling/iteration instances all read iteration 0's count.
  const injectedCount = (): number | undefined => {
    const q = state.env.get(qualify(state, r.id));
    if (q !== undefined) return q;
    return state.env.get(r.id);
  };
  if (r.count === "eos") {
    // §10.7/§11.3: the decoder MUST inject the completed iteration count at the
    // repeat id (qualified per instance); with no injection (static layout
    // preview) the normalize phase yields zero iterations.
    const injected = injectedCount();
    if (injected !== undefined) return Math.max(0, Math.trunc(injected));
    return 0;
  }
  if (typeof r.count === "object" && "until" in r.count) {
    // The `until` termination depends on per-iteration field values the decoder
    // observes while streaming; like `eos`, the count is supplied at the repeat
    // id (qualified per instance). With no injection this yields zero iterations.
    return Math.max(0, Math.trunc(injectedCount() ?? 0));
  }
  return Math.max(0, Math.trunc(evalIn(state, r.count)));
}

function walkSwitch(s: Switch, path: string, state: WalkState): void {
  const sub = `${path}/${s.id}`;
  const disc = Math.trunc(evalIn(state, s.on));
  const arm = selectArm(s.cases, disc);
  if (!arm) return;
  const startOffset = state.offset;
  // Thread the arm key through the whole arm subtree so nested fields (inside a
  // group/optional/bounded/repeat/ref) keep their case attribution (§5).
  const prevSwitchCase = state.switchCase;
  state.switchCase = arm.key;
  try {
    for (const child of arm.struct.fields) walkContainer(child, sub, state);
  } finally {
    if (prevSwitchCase === undefined) delete state.switchCase;
    else state.switchCase = prevSwitchCase;
  }
  recordWireSize(state, s.id, state.offset - startOffset);
}

/** Match in order: exact → list → range → "_" (§5). */
export function selectArm(
  cases: Record<string, Struct>,
  disc: number,
): { key: string; struct: Struct } | undefined {
  const exact = cases[String(disc)];
  if (exact) return { key: String(disc), struct: exact };
  // list keys "a,b,c"
  for (const [key, struct] of Object.entries(cases)) {
    if (key.includes(",")) {
      const vals = key.split(",").map((s) => s.trim());
      if (vals.includes(String(disc))) return { key, struct };
    }
  }
  // range keys "lo-hi"
  for (const [key, struct] of Object.entries(cases)) {
    // Match the validator's canonical range grammar exactly (no leading
    // zeros), so selectArm and the validator agree on which keys are ranges.
    const m = /^(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$/.exec(key);
    if (m) {
      const lo = Number(m[1]);
      const hi = Number(m[2]);
      // A reversed range (lo > hi) matches nothing and is rejected by the
      // validator (§5); guard here so it never silently masks the `_` arm.
      if (lo > hi)
        throw new Error(`selectArm: invalid reversed range key "${key}" (lo > hi).`);
      if (disc >= lo && disc <= hi) return { key, struct };
    }
  }
  if (cases["_"]) return { key: "_", struct: cases["_"] };
  return undefined;
}

function walkEncrypted(e: Encrypted, path: string, state: WalkState): void {
  const sub = `${path}/${e.id}`;
  if (state.viewMode === "wire") {
    const bits = e.wireBits !== undefined
      ? Math.max(0, Math.trunc(evalIn(state, e.wireBits)))
      : sumPlaintextBits(e, state);
    const nf: NormalizedField = {
      id: e.id,
      name: e.name ?? e.id,
      bits,
      absoluteBitOffset: state.offset,
      originalContainerPath: sub,
      ...(e.category !== undefined ? { category: e.category } : {}),
      ...(e.doc !== undefined ? { doc: e.doc } : {}),
      encrypted: true,
      ...(e.contextNote !== undefined ? { encryptedContextNote: e.contextNote } : {}),
    };
    if (state.encryptedStack.length > 0)
      nf.encryptedParentId = state.encryptedStack[state.encryptedStack.length - 1]!.parentId;
    state.out.push(nf);
    state.offset += bits;
    // §4: record the encrypted container's wire footprint so a later
    // `wireSize(e.id)` resolves to its byte size rather than 0.
    recordWireSize(state, e.id, bits);
    return;
  }
  const budgetBits = e.wireBits !== undefined
    ? Math.max(0, Math.trunc(evalIn(state, e.wireBits)))
    : undefined;
  const startOffset = state.offset;
  const frame: EncryptedFrame = {
    parentId: e.id,
    contextNote: e.contextNote ?? "",
    headerProtected: new Set(e.headerProtected ?? []),
  };
  state.encryptedStack.push(frame);
  state.scopeStack.push({ startOffset, kind: "encrypted", ...(budgetBits !== undefined ? { budgetBits } : {}) });
  try {
    for (const child of e.plaintext.fields) walkContainer(child, sub, state);
  } finally {
    state.scopeStack.pop();
    state.encryptedStack.pop();
  }
  // §5: when wireBits gives the ciphertext footprint, the plaintext children's
  // bit sum need not match it (AEAD ciphertext+tag differs from the plaintext
  // layout). Mirror walkBounded: over-consuming the wireBits budget is a runtime
  // error, and under-consumption snaps the cursor to the budget end so every
  // following field gets the correct absoluteBitOffset.
  if (budgetBits !== undefined) {
    const consumed = state.offset - startOffset;
    if (consumed > budgetBits)
      throw new Error(
        `normalize: encrypted scope "${e.id}" over-consumed: plaintext used ${consumed} bits but wireBits is ${budgetBits} bits (§5/§11.2).`,
      );
    if (consumed < budgetBits) state.offset = startOffset + budgetBits;
  }
  // §4: record the encrypted container's wire footprint for wireSize.
  recordWireSize(state, e.id, state.offset - startOffset);
}

function sumPlaintextBits(e: Encrypted, parent: WalkState): number {
  // Use an isolated env copy: this is a throwaway size probe laid out at
  // offset 0 with an empty id prefix, so emit/walkVirtual writes (field
  // values, wireSize keys, virtual values) must NOT leak back into the live
  // parent env, where a later sibling could read the polluted footprint.
  const tmpEnv: PacketEnv = new Map(parent.env);
  const tmp: WalkState = {
    out: [], env: tmpEnv, offset: 0, viewMode: "wire", defs: parent.defs,
    encryptedStack: [], scopeStack: [], groupStack: [], repeatIndexStack: [],
    idPrefix: "", refDepth: parent.refDepth,
  };
  for (const child of e.plaintext.fields) walkContainer(child, e.plaintext.id, tmp);
  return tmp.offset;
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */

export type NormalizeOptions = {
  viewMode?: ViewMode;
  /** Decoder-injected total packet bit count for top-level body budget (§10.1). */
  totalBits?: number;
};

export function normalize(
  packet: Packet,
  env: PacketEnv = new Map(),
  opts: NormalizeOptions = {},
): Normalized {
  const localEnv: PacketEnv = new Map(env);
  const defs = packet.defs ?? {};
  seedDefaults(packet.body, localEnv, defs);
  const state: WalkState = {
    out: [],
    env: localEnv,
    offset: 0,
    viewMode: opts.viewMode ?? "wire",
    defs,
    encryptedStack: [],
    scopeStack: [{ startOffset: 0, kind: "top", ...(opts.totalBits !== undefined ? { budgetBits: opts.totalBits } : {}) }],
    groupStack: [],
    repeatIndexStack: [],
    idPrefix: "",
    refDepth: 0,
  };
  for (const c of packet.body) walkContainer(c, packet.name, state);
  return { fields: state.out, totalBits: state.offset };
}

export function initialEnv(packet: Packet): PacketEnv {
  const env: PacketEnv = new Map();
  seedDefaults(packet.body, env, packet.defs ?? {});
  return env;
}
