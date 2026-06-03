// PSDL semantic validator — walks the Container tree and enforces
// invariants that JSON Schema alone cannot express.

import type {
  Container,
  Encrypted,
  Expr,
  Field,
  Group,
  Packet,
  Repeat,
  Struct,
  Switch,
  Type,
} from "./types.js";
import { VARINT_ENCODINGS } from "./types.js";
import { isField } from "./utils.js";

export function isValidExpr(expr: unknown): expr is Expr {
  if (typeof expr !== "object" || expr === null) return false;
  const e = expr as { kind?: unknown };
  switch (e.kind) {
    case "lit": {
      const v = (expr as { value?: unknown }).value;
      return typeof v === "number" && Number.isFinite(v);
    }
    case "ref":
      return typeof (expr as { field?: unknown }).field === "string";
    case "op": {
      const o = expr as { op?: unknown; a?: unknown; b?: unknown };
      return (
        typeof o.op === "string" &&
        ["+", "-", "*", "/", "%", "<<", ">>"].includes(o.op) &&
        isValidExpr(o.a) &&
        isValidExpr(o.b)
      );
    }
    case "cond": {
      const c = expr as { test?: unknown; t?: unknown; f?: unknown };
      return isValidExpr(c.test) && isValidExpr(c.t) && isValidExpr(c.f);
    }
    case "peek": {
      const p = expr as { bits?: unknown; offset?: unknown };
      if (typeof p.bits !== "number" || !Number.isInteger(p.bits) || p.bits < 1 || p.bits > 64)
        return false;
      if (p.offset !== undefined && !isValidExpr(p.offset)) return false;
      return true;
    }
    default:
      return false;
  }
}

function validateType(type: Type, ctx: string): void {
  switch (type.kind) {
    case "int":
      if (!Number.isInteger(type.bits) || type.bits <= 0)
        throw new Error(`${ctx}: int must have positive integer bits, got ${type.bits}.`);
      return;
    case "bits":
      if (!Number.isInteger(type.n) || type.n <= 0)
        throw new Error(`${ctx}: bits must have positive integer n, got ${type.n}.`);
      return;
    case "bytes":
      if (!isValidExpr(type.n))
        throw new Error(`${ctx}: bytes type has malformed length expression.`);
      return;
    case "enum":
      if (!Number.isInteger(type.bits) || type.bits <= 0)
        throw new Error(`${ctx}: enum must have positive integer bits, got ${type.bits}.`);
      return;
    case "varint": {
      const enc = (type as { encoding: unknown }).encoding;
      if (typeof enc !== "string" || !(VARINT_ENCODINGS as readonly string[]).includes(enc))
        throw new Error(`${ctx}: varint encoding must be one of ${VARINT_ENCODINGS.join(", ")}, got ${String(enc)}.`);
      return;
    }
    case "berLength":
      return;
    default: {
      const bad = (type as { kind: string }).kind;
      throw new Error(`${ctx}: unknown type kind "${bad}".`);
    }
  }
}

function validateField(field: Field, ctx: string): void {
  if (typeof field.id !== "string" || field.id.length === 0)
    throw new Error(`${ctx}: field is missing an id.`);
  if (typeof field.name !== "string")
    throw new Error(`${ctx}: field "${field.id}" is missing a name.`);
  if (!field.type)
    throw new Error(`${ctx}: field "${field.id}" is missing a type.`);
  validateType(field.type, `${ctx}/${field.id}`);
  if (field.byteOrder !== undefined && field.byteOrder !== "BE" && field.byteOrder !== "LE")
    throw new Error(`${ctx}/${field.id}: byteOrder must be 'BE' or 'LE', got "${String(field.byteOrder)}".`);
}

function validateGroup(g: Group, ctx: string): void {
  if (!Array.isArray(g.children))
    throw new Error(`${ctx}: group "${g.id}" must have a children array.`);
  const sub = `${ctx}/${g.id}`;
  for (const child of g.children) validateContainer(child, sub);
}

function validateRepeat(r: Repeat, ctx: string): void {
  const sub = `${ctx}/${r.id}`;
  if (!r.element || typeof r.element !== "object")
    throw new Error(`${sub}: repeat is missing element struct.`);
  validateStruct(r.element, sub);
}

function validateSwitch(s: Switch, ctx: string): void {
  const sub = `${ctx}/${s.id}`;
  if (!isValidExpr(s.on))
    throw new Error(`${sub}: switch has invalid discriminator expression.`);
  if (!s.cases || typeof s.cases !== "object")
    throw new Error(`${sub}: switch is missing cases.`);
  for (const [key, struct] of Object.entries(s.cases)) {
    if (typeof key !== "string")
      throw new Error(`${sub}: switch case key must be a string.`);
    validateStruct(struct, `${sub}/${key}`);
  }
  if (s.default) validateStruct(s.default, `${sub}/default`);
}

function validateEncrypted(e: Encrypted, ctx: string): void {
  const sub = `${ctx}/${e.id}`;
  if (!e.plaintext || !Array.isArray(e.plaintext.fields))
    throw new Error(`${sub}: encrypted container must have a plaintext struct.`);
  if (typeof e.contextNote !== "string" || e.contextNote.length === 0)
    throw new Error(`${sub}: encrypted container must have a non-empty contextNote.`);
  if (e.wireBits !== undefined && !isValidExpr(e.wireBits))
    throw new Error(`${sub}: encrypted wireBits has malformed expression.`);
  validateStruct(e.plaintext, sub);
}

export function validateContainer(c: Container, ctx: string): void {
  if (isField(c)) { validateField(c, ctx); return; }
  switch (c.kind) {
    case "group": validateGroup(c, ctx); return;
    case "repeat": validateRepeat(c, ctx); return;
    case "switch": validateSwitch(c, ctx); return;
    case "encrypted": validateEncrypted(c, ctx); return;
    case "optional":
      if (!isValidExpr(c.when))
        throw new Error(`${ctx}: optional has invalid 'when' expression.`);
      validateField(c.field, ctx);
      return;
  }
}

function validateStruct(s: Struct, ctx: string): void {
  if (typeof s.id !== "string" || s.id.length === 0)
    throw new Error(`${ctx}: struct is missing an id.`);
  if (!Array.isArray(s.fields))
    throw new Error(`${ctx}/${s.id}: struct must have a fields array.`);
  for (const child of s.fields) validateContainer(child, `${ctx}/${s.id}`);
}

export type ValidationError = { message: string };

export function validatePacket(packet: Packet): ValidationError[] {
  const errors: ValidationError[] = [];
  const wrap = (fn: () => void) => {
    try { fn(); } catch (e) { errors.push({ message: String(e) }); }
  };
  wrap(() => {
    if (typeof packet.name !== "string" || packet.name.length === 0)
      throw new Error("Packet must have a non-empty name.");
    if (!Number.isInteger(packet.rowBits) || packet.rowBits <= 0)
      throw new Error(`rowBits must be a positive integer, got ${String(packet.rowBits)}.`);
    if (!Array.isArray(packet.body))
      throw new Error("Packet must have a body array.");
    if (packet.byteOrder !== undefined && packet.byteOrder !== "BE" && packet.byteOrder !== "LE")
      throw new Error(`byteOrder must be 'BE' or 'LE', got "${String(packet.byteOrder)}".`);
  });
  for (const c of packet.body ?? []) {
    wrap(() => validateContainer(c, packet.name));
  }
  return errors;
}
