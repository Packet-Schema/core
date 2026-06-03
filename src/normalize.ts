import { evalExpr } from "./expr.js";
import { isField } from "./utils.js";
import type {
  Container,
  Encrypted,
  Field,
  Group,
  Normalized,
  NormalizedField,
  Packet,
  PacketEnv,
  Repeat,
  Struct,
  Switch,
  Type,
  ViewMode,
} from "./types.js";

export function berLenEnvKey(fieldId: string): string {
  return `__berLen__${fieldId}`;
}

export function typeBits(type: Type, env: PacketEnv, fieldId?: string): number {
  switch (type.kind) {
    case "int":
    case "enum":
      return type.bits;
    case "bits":
      return type.n;
    case "bytes":
      return evalExpr(type.n, env) * 8;
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

function seedDefaults(containers: Container[], env: PacketEnv): void {
  for (const c of containers) {
    if (isField(c)) {
      if (c.defaultValue !== undefined && !env.has(c.id))
        env.set(c.id, c.defaultValue);
    } else if (c.kind === "group") {
      seedDefaults(c.children, env);
    } else if (c.kind === "encrypted") {
      seedDefaults(c.plaintext.fields, env);
    } else if (c.kind === "optional") {
      if (c.field.defaultValue !== undefined && !env.has(c.field.id))
        env.set(c.field.id, c.field.defaultValue);
    }
  }
}

type EncryptedFrame = {
  parentId: string;
  contextNote: string;
  headerProtected: Set<string>;
};

type WalkState = {
  out: NormalizedField[];
  env: PacketEnv;
  offset: number;
  viewMode: ViewMode;
  encryptedStack: EncryptedFrame[];
  repeatIndex?: number;
  groupStack?: Array<{ id: string; name: string }>;
  repeatIndexStack?: number[];
};

type EmitExtra = Pick<NormalizedField, "repeatIndex" | "switchCase">;

function emit(state: WalkState, field: Field, path: string, extra: EmitExtra = {}): void {
  const bits = typeBits(field.type, state.env, field.id);
  const repeatIndex = extra.repeatIndex ?? state.repeatIndex;
  const nf: NormalizedField = {
    id: repeatIndex !== undefined ? `${field.id}#${repeatIndex}` : field.id,
    name: field.name,
    bits,
    absoluteBitOffset: state.offset,
    originalContainerPath: path,
    category: field.category,
    doc: field.doc,
    ...extra,
    ...(repeatIndex !== undefined ? { repeatIndex } : {}),
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
  if (state.groupStack && state.groupStack.length > 0) {
    const top = state.groupStack[state.groupStack.length - 1]!;
    const indexTag =
      state.repeatIndexStack && state.repeatIndexStack.length > 0
        ? state.repeatIndexStack.join("_")
        : null;
    nf.groupId = indexTag !== null ? `${top.id}#${indexTag}` : top.id;
    nf.groupName = top.name;
  }
  state.out.push(nf);
  state.offset += bits;
}

function walkContainer(c: Container, path: string, state: WalkState): void {
  if (isField(c)) { emit(state, c, path); return; }
  switch (c.kind) {
    case "group": walkGroup(c, path, state); return;
    case "repeat": walkRepeat(c, path, state); return;
    case "switch": walkSwitch(c, path, state); return;
    case "encrypted": walkEncrypted(c, path, state); return;
    case "optional": {
      let test = 0;
      try { test = evalExpr(c.when, state.env); } catch { test = 0; }
      if (test !== 0) emit(state, c.field, path);
      return;
    }
  }
}

function walkGroup(g: Group, path: string, state: WalkState): void {
  const sub = `${path}/${g.id}`;
  const stack = state.groupStack ?? [];
  state.groupStack = [...stack, { id: g.id, name: g.name ?? g.id }];
  for (const child of g.children) walkContainer(child, sub, state);
  state.groupStack = stack;
}

function walkRepeat(r: Repeat, path: string, state: WalkState): void {
  const sub = `${path}/${r.id}`;
  const count = resolveRepeatCount(r, state);
  const prevRepeatIndex = state.repeatIndex;
  const prevStack = state.repeatIndexStack ?? [];
  for (let i = 0; i < count; i++) {
    const innerPath = `${sub}[${i}]`;
    state.repeatIndex = i;
    state.repeatIndexStack = [...prevStack, i];
    for (const child of r.element.fields) {
      if (isField(child)) emit(state, child, innerPath, { repeatIndex: i });
      else walkContainer(child, innerPath, state);
    }
  }
  state.repeatIndex = prevRepeatIndex;
  state.repeatIndexStack = prevStack.length > 0 ? prevStack : undefined;
}

function resolveRepeatCount(r: Repeat, state: WalkState): number {
  if (r.count === "eos") return state.env.get(r.id) ?? 0;
  if (typeof r.count === "object" && "until" in r.count) return state.env.get(r.id) ?? 0;
  return Math.max(0, Math.trunc(evalExpr(r.count, state.env)));
}

function walkSwitch(s: Switch, path: string, state: WalkState): void {
  const sub = `${path}/${s.id}`;
  const disc = evalExpr(s.on, state.env);
  const key = String(disc);
  const chosen = s.cases[key] ?? s.default;
  if (!chosen) return;
  for (const child of chosen.fields) {
    if (isField(child)) emit(state, child, sub, { switchCase: key });
    else walkContainer(child, sub, state);
  }
}

function walkEncrypted(e: Encrypted, path: string, state: WalkState): void {
  const sub = `${path}/${e.id}`;
  if (state.viewMode === "wire") {
    const bits =
      e.wireBits !== undefined
        ? Math.max(0, Math.trunc(evalExpr(e.wireBits, state.env)))
        : sumPlaintextBits(e.plaintext, state.env);
    const nf: NormalizedField = {
      id: e.id,
      name: e.name ?? e.id,
      bits,
      absoluteBitOffset: state.offset,
      originalContainerPath: sub,
      category: e.category,
      doc: e.doc,
      encrypted: true,
      encryptedContextNote: e.contextNote,
    };
    if (state.encryptedStack.length > 0)
      nf.encryptedParentId = state.encryptedStack[state.encryptedStack.length - 1]!.parentId;
    state.out.push(nf);
    state.offset += bits;
    return;
  }
  const frame: EncryptedFrame = {
    parentId: e.id,
    contextNote: e.contextNote,
    headerProtected: new Set(e.headerProtected ?? []),
  };
  state.encryptedStack.push(frame);
  try {
    for (const child of e.plaintext.fields) walkContainer(child, sub, state);
  } finally {
    state.encryptedStack.pop();
  }
}

function sumPlaintextBits(plaintext: Struct, env: PacketEnv): number {
  const tmp: WalkState = { out: [], env, offset: 0, viewMode: "wire", encryptedStack: [] };
  for (const child of plaintext.fields) walkContainer(child, plaintext.id, tmp);
  return tmp.offset;
}

export type NormalizeOptions = { viewMode?: ViewMode };

export function normalize(
  packet: Packet,
  env: PacketEnv = new Map(),
  opts: NormalizeOptions = {},
): Normalized {
  const localEnv: PacketEnv = new Map(env);
  seedDefaults(packet.body, localEnv);
  const state: WalkState = {
    out: [],
    env: localEnv,
    offset: 0,
    viewMode: opts.viewMode ?? "wire",
    encryptedStack: [],
  };
  for (const c of packet.body) walkContainer(c, packet.name, state);
  return { fields: state.out, totalBits: state.offset };
}

export function initialEnv(packet: Packet): PacketEnv {
  const env: PacketEnv = new Map();
  seedDefaults(packet.body, env);
  return env;
}
