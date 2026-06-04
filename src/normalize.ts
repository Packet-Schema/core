// normalize.ts — walks the Container tree into a flat NormalizedField list.
//
// Implements the §10 processing model: seed phase (§10.2) then a forward,
// single-pass parse that injects context-dependent expression values
// (remaining/enclosingBits/wireSize/prevIter) into the env as it goes.

import { evalExpr, evalExprOr, enclosingBitsEnvKey, prevIterEnvKey, remainingEnvKey, wireSizeEnvKey } from "./expr.js";
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

/** Maximum recursive-def expansion depth (decoder is the real authority, §6). */
const MAX_REF_DEPTH = 64;

export function typeBits(type: Type, env: PacketEnv, fieldId?: string): number {
  switch (type.kind) {
    case "int":
    case "enum":
      return type.bits;
    case "bits":
      return type.n;
    case "bytes": {
      const nExpr: Expr = type.n === "auto" ? { kind: "remaining" } : type.n;
      return Math.max(0, Math.trunc(evalExprOr(nExpr, env))) * 8;
    }
    case "varint":
      if (fieldId !== undefined) {
        const v = env.get(fieldId);
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

function seedDefaults(containers: Container[], env: PacketEnv, defs: Record<string, NamedStruct>, depth = 0): void {
  if (depth > MAX_REF_DEPTH) return;
  for (const c of containers) {
    if (isField(c)) {
      const seed = c.const ?? c.defaultValue;
      if (seed !== undefined && !env.has(c.id)) env.set(c.id, seed);
    } else if (c.kind === "group") {
      seedDefaults(c.children, env, defs, depth);
    } else if (c.kind === "bounded") {
      seedDefaults(c.fields, env, defs, depth);
    } else if (c.kind === "encrypted") {
      seedDefaults(c.plaintext.fields, env, defs, depth);
    } else if (c.kind === "optional") {
      seedDefaults([c.container], env, defs, depth);
    } else if (c.kind === "repeat") {
      seedDefaults(c.element.fields, env, defs, depth);
    } else if (c.kind === "switch") {
      for (const arm of Object.values(c.cases)) seedDefaults(arm.fields, env, defs, depth);
    } else if (c.kind === "ref") {
      const def = defs[c.ref];
      if (def) seedDefaults(def.fields, env, defs, depth + 1);
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

/** A scope-providing container that carries remaining/enclosingBits (§4). */
type ScopeFrame = {
  startOffset: number;
  budgetBits?: number;
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
};

type EmitExtra = Pick<NormalizedField, "switchCase">;

/** Inject remaining/enclosingBits for the innermost budgeted scope (§4). */
function injectScopeBudget(state: WalkState): void {
  let frame: ScopeFrame | undefined;
  for (let i = state.scopeStack.length - 1; i >= 0; i--) {
    const f = state.scopeStack[i]!;
    if (f.budgetBits !== undefined) { frame = f; break; }
  }
  if (frame === undefined) {
    state.env.delete(remainingEnvKey());
    state.env.delete(enclosingBitsEnvKey());
    return;
  }
  const consumed = state.offset - frame.startOffset;
  const remainingBits = Math.max(0, frame.budgetBits! - consumed);
  state.env.set(remainingEnvKey(), Math.floor(remainingBits / 8));
  state.env.set(enclosingBitsEnvKey(), frame.budgetBits!);
}

/** Evaluate an expression with scope budget freshly injected (§4, §10.3). */
function evalIn(state: WalkState, expr: Expr): number {
  injectScopeBudget(state);
  return evalExprOr(expr, state.env);
}

function repeatSuffix(state: WalkState): string {
  return state.repeatIndexStack.length > 0 ? `#${state.repeatIndexStack.join("_")}` : "";
}

function emit(state: WalkState, field: Field, path: string, extra: EmitExtra = {}): void {
  injectScopeBudget(state);
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
    ...extra,
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
  // Record wire footprint for wireSize (parse-direction; §4).
  state.env.set(wireSizeEnvKey(field.id), Math.floor(bits / 8));
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
  // Cap padding at the innermost budgeted scope end (§5, SCTP last chunk).
  for (let i = state.scopeStack.length - 1; i >= 0; i--) {
    const f = state.scopeStack[i]!;
    if (f.budgetBits !== undefined) {
      const avail = f.budgetBits - (state.offset - f.startOffset);
      if (padBits > avail) padBits = Math.max(0, avail);
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
  state.env.set(wireSizeEnvKey(r.id), Math.floor((state.offset - startOffset) / 8));
  state.refDepth--;
  state.idPrefix = prevPrefix;
}

function walkGroup(g: Group, path: string, state: WalkState): void {
  const sub = `${path}/${g.id}`;
  const prev = state.groupStack;
  state.groupStack = [...prev, { id: g.id, name: g.name ?? g.id }];
  const startOffset = state.offset;
  for (const child of g.children) walkContainer(child, sub, state);
  state.env.set(wireSizeEnvKey(g.id), Math.floor((state.offset - startOffset) / 8));
  state.groupStack = prev;
}

function walkBounded(b: Bounded, path: string, state: WalkState): void {
  const sub = `${path}/${b.id}`;
  const budgetBits = Math.max(0, Math.trunc(evalIn(state, b.bytes))) * 8;
  const startOffset = state.offset;
  state.scopeStack.push({ startOffset, budgetBits });
  for (const child of b.fields) walkContainer(child, sub, state);
  state.scopeStack.pop();
  // Advance to the scope end even if the children under-consumed.
  const consumed = state.offset - startOffset;
  if (consumed < budgetBits) state.offset = startOffset + budgetBits;
  state.env.set(wireSizeEnvKey(b.id), Math.floor((state.offset - startOffset) / 8));
}

function walkRepeat(r: Repeat, path: string, state: WalkState): void {
  const sub = `${path}/${r.id}`;
  const count = resolveRepeatCount(r, state);
  const startOffset = state.offset;
  const prevStack = state.repeatIndexStack;
  for (let i = 0; i < count; i++) {
    state.repeatIndexStack = [...prevStack, i];
    const innerPath = `${sub}[${i}]`;
    // Inject prevIter values from the just-completed iteration (§10.4).
    if (i > 0) {
      for (const child of r.element.fields) {
        if (isField(child)) {
          const prevId = `${child.id}#${[...prevStack, i - 1].join("_")}`;
          const v = state.env.get(prevId);
          if (v !== undefined) state.env.set(prevIterEnvKey(child.id), v);
        }
      }
    }
    for (const child of r.element.fields) walkContainer(child, innerPath, state);
  }
  state.repeatIndexStack = prevStack;
  state.env.set(wireSizeEnvKey(r.id), Math.floor((state.offset - startOffset) / 8));
}

function resolveRepeatCount(r: Repeat, state: WalkState): number {
  if (r.count === "eos") {
    const injected = state.env.get(r.id);
    if (injected !== undefined) return Math.max(0, Math.trunc(injected));
    // Fall back to consuming the innermost scope budget if no count injected.
    return 0;
  }
  if (typeof r.count === "object" && "until" in r.count) {
    return Math.max(0, Math.trunc(state.env.get(r.id) ?? 0));
  }
  return Math.max(0, Math.trunc(evalIn(state, r.count)));
}

function walkSwitch(s: Switch, path: string, state: WalkState): void {
  const sub = `${path}/${s.id}`;
  const disc = Math.trunc(evalIn(state, s.on));
  const arm = selectArm(s.cases, disc);
  if (!arm) return;
  const startOffset = state.offset;
  for (const child of arm.struct.fields) {
    if (isField(child)) emit(state, child, sub, { switchCase: arm.key });
    else walkContainer(child, sub, state);
  }
  state.env.set(wireSizeEnvKey(s.id), Math.floor((state.offset - startOffset) / 8));
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
    const m = /^(\d+)-(\d+)$/.exec(key);
    if (m) {
      const lo = Number(m[1]);
      const hi = Number(m[2]);
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
    return;
  }
  const budgetBits = e.wireBits !== undefined
    ? Math.max(0, Math.trunc(evalIn(state, e.wireBits)))
    : undefined;
  const frame: EncryptedFrame = {
    parentId: e.id,
    contextNote: e.contextNote ?? "",
    headerProtected: new Set(e.headerProtected ?? []),
  };
  state.encryptedStack.push(frame);
  state.scopeStack.push({ startOffset: state.offset, ...(budgetBits !== undefined ? { budgetBits } : {}) });
  try {
    for (const child of e.plaintext.fields) walkContainer(child, sub, state);
  } finally {
    state.scopeStack.pop();
    state.encryptedStack.pop();
  }
}

function sumPlaintextBits(e: Encrypted, parent: WalkState): number {
  const tmp: WalkState = {
    out: [], env: parent.env, offset: 0, viewMode: "wire", defs: parent.defs,
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
    scopeStack: [{ startOffset: 0, ...(opts.totalBits !== undefined ? { budgetBits: opts.totalBits } : {}) }],
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
