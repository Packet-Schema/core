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
/** Ternary bit-pattern for ValueEntry.pattern (§5.3): 0, 1, or x/X. */
const PATTERN_RE = /^[01xX]+$/;
const SWITCH_KEY_RE = /^(_|(0|[1-9][0-9]*)|(0|[1-9][0-9]*)-(0|[1-9][0-9]*)|(0|[1-9][0-9]*)(,(0|[1-9][0-9]*))+)$/;
/** Hex-string form for wide checksum params (§8, D9): `^0x[0-9A-Fa-f]+$`. */
const HEX_PARAM_RE = /^0x[0-9A-Fa-f]+$/;

/** True if a `bytes.n` is the delimiter form, however malformed (§3, D3). */
function isBytesDelimitedShape(n: unknown): boolean {
  return typeof n === "object" && n !== null && !Array.isArray(n) && "delimiter" in n;
}
const NORM_LEVELS: ReadonlySet<string> = new Set(["must", "should", "may"]);
/** The closed nine-token category set (§5.1, schema CategoryToken enum). */
const CATEGORY_TOKEN_SET: ReadonlySet<string> = new Set([
  "addressing", "identifier", "length", "type", "flags",
  "reserved", "checksum", "variable", "payload-marker",
]);
/**
 * Named checksum algorithms that do NOT use the CRC parameter model (§8). Using
 * `checksumParams` with one of these is a validation error (§11.1) because they
 * have fixed internal parameters structurally incompatible with the CRC set.
 */
const NON_CRC_CHECKSUM_ALGORITHMS: ReadonlySet<string> = new Set(["internet", "adler32"]);
/** ValueEntry keys (schema ValueEntry, `additionalProperties: false`, §5.3). */
const VALUE_ENTRY_KEYS: ReadonlySet<string> = new Set([
  "value", "range", "pattern", "name", "label", "doc", "level", "meta",
]);
/** Enum variant object keys (schema EnumVariant, `additionalProperties: false`, §3). */
const ENUM_VARIANT_KEYS: ReadonlySet<string> = new Set(["label", "doc", "level", "meta"]);
/** Constraint keys (schema Constraint, `additionalProperties: false`, §9). */
const CONSTRAINT_KEYS: ReadonlySet<string> = new Set(["lhs", "rhs", "doc", "level"]);

/* ------------------------------------------------------------------ *
 * RFC provenance shape (§5.4)
 * ------------------------------------------------------------------ */

/**
 * A single `updates` entry (§5.4): a bare integer RFC number, or an object
 * `{ rfc (required integer), section? (string) }` with no surplus keys. A bare
 * number N means `{ rfc: N }` (no section); the object form names the section
 * of that updating RFC.
 */
function isValidUpdateRef(u: unknown): boolean {
  if (typeof u === "number") return Number.isInteger(u);
  if (typeof u !== "object" || u === null || Array.isArray(u)) return false;
  const o = u as { rfc?: unknown; section?: unknown };
  for (const key of Object.keys(o)) {
    if (key !== "rfc" && key !== "section") return false;
  }
  if (!Number.isInteger(o.rfc)) return false;
  if (o.section !== undefined && typeof o.section !== "string") return false;
  return true;
}

/** RfcRef shape (§5.4): a bare integer, or `{ defined, updates? }` with no surplus keys. */
function isValidRfcRef(v: unknown): boolean {
  if (typeof v === "number") return Number.isInteger(v);
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as { defined?: unknown; updates?: unknown };
  for (const key of Object.keys(o)) {
    if (key !== "defined" && key !== "updates") return false;
  }
  if (!Number.isInteger(o.defined)) return false;
  if (o.updates !== undefined &&
      (!Array.isArray(o.updates) || !o.updates.every((u) => isValidUpdateRef(u))))
    return false;
  return true;
}

/** FieldMeta keys (schema FieldMeta, `additionalProperties: false`). */
const FIELD_META_KEYS: ReadonlySet<string> = new Set(["rfc", "section"]);
/** PacketMeta keys (schema PacketMeta additionally allows `aliases`, `tags`, `family`). */
const PACKET_META_KEYS: ReadonlySet<string> = new Set(["rfc", "section", "aliases", "tags", "family"]);

/**
 * Lightweight `meta` shape check (§5.4), mirroring the schema's FieldMeta /
 * PacketMeta / RfcRef defs so the two validation layers agree on what a
 * well-formed provenance annotation is (the schema rejects these shapes too):
 * unknown keys are rejected (`additionalProperties: false`), `section` must be
 * a string, `aliases` (packet meta only) must be an array of strings.
 */
function validateMeta(
  meta: unknown,
  ctx: string,
  errors: ValidationError[],
  allowedKeys: ReadonlySet<string> = FIELD_META_KEYS,
): void {
  if (meta === undefined) return;
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    errors.push({ message: `${ctx}: meta must be an object (§5.4).` });
    return;
  }
  for (const key of Object.keys(meta)) {
    if (!allowedKeys.has(key))
      errors.push({ message: `${ctx}: meta has unknown key "${key}" (allowed: ${[...allowedKeys].join(", ")}) (§5.4).` });
  }
  const { rfc, section, aliases, tags, family } = meta as
    { rfc?: unknown; section?: unknown; aliases?: unknown; tags?: unknown; family?: unknown };
  if (rfc !== undefined && !isValidRfcRef(rfc))
    errors.push({ message: `${ctx}: meta.rfc must be an integer or { defined, updates? } where each updates entry is an integer or { rfc, section? } (§5.4).` });
  if (section !== undefined && typeof section !== "string")
    errors.push({ message: `${ctx}: meta.section must be a string (e.g. "3.1") (§5.4).` });
  if (allowedKeys.has("aliases") && aliases !== undefined &&
      (!Array.isArray(aliases) || !aliases.every((a) => typeof a === "string")))
    errors.push({ message: `${ctx}: meta.aliases must be an array of strings.` });
  // §1.1: free-form catalog classification — the language checks only the shape
  // (string[] / string); the vocabulary is governed by the catalog layer.
  if (allowedKeys.has("tags") && tags !== undefined &&
      (!Array.isArray(tags) || !tags.every((t) => typeof t === "string")))
    errors.push({ message: `${ctx}: meta.tags must be an array of strings (§1.1).` });
  if (allowedKeys.has("family") && family !== undefined && typeof family !== "string")
    errors.push({ message: `${ctx}: meta.family must be a string (§1.1).` });
}

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
  /**
   * §10.1/§D11: the richer document-order set a body-expression leaf `ref`/
   * `wireSize` may name and have it PRECEDE the expression: full dotted +
   * bare-tail + local-ref-expanded ids of every container closed so far (mirror
   * of `documentDeclaredIds`, accumulated in document order via
   * collectSubtreeDeclaredIds at each container's post-dispatch close point). A
   * target present in `documentDeclaredIds` but absent here is a forward/self
   * reference. Undefined ⇒ the forward-order branch is skipped (e.g. constraints,
   * which are §10.1-exempt, and defs).
   */
  declaredExprIds?: Set<string>;
  /** Container ids currently open on the parse stack (not yet closed). */
  openIds: Set<string>;
  /** All repeat container ids anywhere in the document. */
  repeatIds: Set<string>;
  /**
   * Every id a body/constraint expression `ref`/`wireSize` may name: authored
   * leaf/container ids, local-ref-expanded dotted ids, the bare tail segment of
   * each expanded id (for §6 nearest-preceding bare-id resolution), and repeat
   * ids (§D11). Undefined ⇒ the existence check is skipped (e.g. inside defs).
   */
  documentDeclaredIds?: Set<string>;
  /** Import `as` prefixes; a dotted ref whose head is one of these is deferred to the import layer (§1.2). */
  importPrefixes?: Set<string>;
};

function validateExprPlacement(
  expr: Expr,
  slot: ExprSlot,
  ctx: string,
  errors: ValidationError[],
  pc?: PlacementCtx,
  /**
   * §10.7 carve-out (passed ONLY from the two `repeat.count`/`repeat.until`
   * call sites in validateRepeat): the set of referenceable ids contributed by
   * the SAME repeat's element subtree. A leaf `ref` naming one of these resolves
   * to the just-completed iteration's field value (§10.7) and is therefore
   * exempt from the §10.1 forward-reference rule. The set is built from
   * `element.fields` only, so it excludes the repeat container's own id and any
   * non-element sibling — a self-ref to the repeat id or a forward ref to a
   * later sibling still errors. Undefined at every other call site.
   */
  elementRefExempt?: ReadonlySet<string>,
): void {
  walkExpr(expr, (e) => {
    if (e.kind === "peek" && !PEEK_ALLOWED.has(slot))
      errors.push({ message: `${ctx}: peek may not appear in ${slot} (allowed: switch.on, optional.when, repeat.count/until).` });
    if (e.kind === "enclosingField" && slot !== "constraint")
      errors.push({ message: `${ctx}: enclosingField may only appear in constraints, not ${slot}.` });
    if (e.kind === "prevIter" && slot !== "repeat.count" && slot !== "repeat.until")
      errors.push({ message: `${ctx}: prevIter may only appear in repeat.count or repeat.until, not ${slot}.` });
    if (pc === undefined) return;
    // §D11: leaf `ref`/`wireSize` existence check. Applies to body and
    // constraint expressions (pc present). A target naming nothing declared
    // anywhere in the document is a typo and a validation error.
    if (pc.documentDeclaredIds !== undefined &&
        (e.kind === "ref" || e.kind === "wireSize")) {
      const id = e.kind === "ref" ? e.field : e.target;
      const head = id.includes(".") ? id.slice(0, id.indexOf(".")) : id;
      if (id.includes("#")) {
        errors.push({ message: `${ctx}: '#'-qualified ids may not appear in expressions (repeat-indexed instances are not referenceable, §2/§10.4).` });
      } else if (id.includes(".") && pc.importPrefixes?.has(head)) {
        // Import-qualified (e.g. addr.ipv4Addr.oct0): resolution is deferred to
        // the import-resolving layer (§1.2); the core validator does not check it.
      } else if (!pc.documentDeclaredIds.has(id)) {
        errors.push({ message: `${ctx}: ${e.kind === "ref" ? "ref" : "wireSize"} target "${id}" is not declared anywhere in the document (§11.1).` });
      }
    }
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
      // §10.1/§11.1: a leaf `ref` in a body slot may name only a field/container
      // that PRECEDES it in document order. A ref to a repeat container id keeps
      // its specific message; every other leaf ref (including a self-size ref, a
      // ref to a later field, or a dotted ref-expanded target not yet closed) is
      // caught by the general forward branch. The check is gated on
      // `declaredExprIds` (document-order-so-far) and on the target EXISTING in
      // `documentDeclaredIds` — a typo is already reported above as "not declared
      // anywhere", so it must not also be reported here. Import-/`#`-qualified ids
      // took their early-out branches above and are not re-flagged. Constraints
      // are §10.1-exempt: `declaredExprIds` is undefined for them, so this branch
      // is skipped.
      if (e.kind === "ref" && pc.declaredExprIds !== undefined &&
          pc.documentDeclaredIds !== undefined && !pc.declaredExprIds.has(e.field) &&
          !e.field.includes("#") &&
          !(e.field.includes(".") && pc.importPrefixes?.has(e.field.slice(0, e.field.indexOf("."))))) {
        if (pc.repeatIds.has(e.field) && !pc.declaredIds.has(e.field)) {
          errors.push({ message: `${ctx}: ref to repeat container id "${e.field}" precedes that repeat in document order (§11.1).` });
        } else if (pc.documentDeclaredIds.has(e.field) && !elementRefExempt?.has(e.field)) {
          // §10.7 carve-out: a `repeat.count`/`repeat.count.until` ordinary ref
          // to a field of the SAME repeat's element is NOT forward — it resolves
          // to the just-completed iteration's value. `elementRefExempt` carries
          // exactly those element-field ids (and only at those two call sites),
          // so the repeat's own id and any later sibling still fall through to
          // this error (excluded from the exempt set by construction).
          errors.push({ message: `${ctx}: ref target "${e.field}" does not precede this expression in document order, or refers to its own container (a self-size ref); a body expression may reference only fields declared before it (§10.1/§11.1).` });
        }
      }
    }
  });
}

/* ------------------------------------------------------------------ *
 * Types
 * ------------------------------------------------------------------ */

function validateType(type: Type, ctx: string, errors: ValidationError[], pc?: PlacementCtx): void {
  switch (type.kind) {
    case "int":
      if (!Number.isInteger(type.bits) || type.bits <= 0)
        errors.push({ message: `${ctx}: int must have positive integer bits, got ${type.bits}.` });
      return;
    case "enum": {
      if (!Number.isInteger(type.bits) || type.bits <= 0)
        errors.push({ message: `${ctx}: enum must have positive integer bits, got ${type.bits}.` });
      // `!Array.isArray`: a YAML list of labels is not a variants table — the
      // schema's `variants: { type: object }` rejects arrays, so reject here
      // too (typeof [] === "object" would otherwise let it through).
      if (type.variants && typeof type.variants === "object" && !Array.isArray(type.variants)) {
        for (const [k, v] of Object.entries(type.variants as Record<string, unknown>)) {
          if (!DECIMAL_INT_RE.test(k))
            errors.push({ message: `${ctx}: enum variant key "${k}" must be a non-negative decimal integer (§3).` });
          if (typeof v === "object" && v !== null) {
            const o = v as { label?: unknown; doc?: unknown; level?: unknown; meta?: unknown };
            for (const key of Object.keys(o)) {
              // Mirrors the schema's EnumVariant `additionalProperties: false`
              // so a typo'd annotation key cannot silently vanish (§3, §5.4).
              if (!ENUM_VARIANT_KEYS.has(key))
                errors.push({ message: `${ctx}: enum variant "${k}" has unknown key "${key}" (allowed: ${[...ENUM_VARIANT_KEYS].join(", ")}) (§3).` });
            }
            if (typeof o.label !== "string")
              errors.push({ message: `${ctx}: enum variant "${k}" must have a string label (§3).` });
            // Mirrors the schema's EnumVariant `doc` `type: string` (§3).
            if (o.doc !== undefined && typeof o.doc !== "string")
              errors.push({ message: `${ctx}: enum variant "${k}" doc must be a string (§3).` });
            if (o.level !== undefined && !NORM_LEVELS.has(o.level as string))
              errors.push({ message: `${ctx}: enum variant "${k}" has invalid level "${String(o.level)}" (must be must|should|may).` });
            validateMeta(o.meta, `${ctx}: enum variant "${k}"`, errors);
          } else if (typeof v !== "string") {
            errors.push({ message: `${ctx}: enum variant "${k}" must be a string label or an object with a label (§3).` });
          }
        }
      } else {
        // Mirrors the schema's `required: [kind, bits, variants]` so the two
        // validation layers agree (§3). An empty `{}` table is fine.
        errors.push({ message: `${ctx}: enum must have a variants object (§3).` });
      }
      return;
    }
    case "bits":
      if (!Number.isInteger(type.n) || type.n <= 0)
        errors.push({ message: `${ctx}: bits must have positive integer n, got ${type.n}.` });
      return;
    case "bytes":
      // §3 (D3): bytes.n is either an Expr or the delimiter form.
      if (isBytesDelimitedShape(type.n)) {
        const delim = (type.n as { delimiter: unknown }).delimiter;
        // The delimiter form accepts only the `delimiter` key (mirrors schema
        // BytesDelimited additionalProperties:false).
        for (const key of Object.keys(type.n as Record<string, unknown>))
          if (key !== "delimiter")
            errors.push({ message: `${ctx}: bytes.n delimiter form accepts only the "delimiter" key (got "${key}") (§3).` });
        if (!Array.isArray(delim) || delim.length < 1)
          errors.push({ message: `${ctx}: bytes.n delimiter must be a non-empty array of byte integers (§3/§11.1).` });
        else if (!delim.every((b) => Number.isInteger(b) && (b as number) >= 0 && (b as number) <= 255))
          errors.push({ message: `${ctx}: bytes.n delimiter elements must be integers in 0–255 (§3/§11.1).` });
      } else if (!isValidExpr(type.n))
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

/**
 * §8/§11.1 (D9): validate `checksumParams` width and the polynomial/initValue/
 * finalXOR numeric forms. A bare integer is allowed only when it is a safe
 * integer (≤ 2^53−1); a wider value MUST use the `^0x[0-9A-Fa-f]+$` hex string
 * so its full 64-bit precision survives. A non-int/bits checksum field (e.g. a
 * `bytes` checksum) requires an explicit `width` because its declared bit width
 * is not unique.
 */
function validateChecksumParams(field: Field, ctx: string, errors: ValidationError[]): void {
  const p = field.checksumParams!;
  for (const key of ["polynomial", "initValue", "finalXOR"] as const) {
    const v = p[key];
    if (v === undefined) continue;
    if (typeof v === "string") {
      if (!HEX_PARAM_RE.test(v))
        errors.push({ message: `${ctx}: checksumParams.${key} hex string "${v}" must match ^0x[0-9A-Fa-f]+$ (§8/§11.1).` });
    } else if (typeof v === "number") {
      if (!Number.isInteger(v) || v < 0)
        errors.push({ message: `${ctx}: checksumParams.${key} must be a non-negative integer or a 0x hex string (§8).` });
      else if (!Number.isSafeInteger(v))
        errors.push({ message: `${ctx}: checksumParams.${key} exceeds 2^53−1 and must be written as a ^0x[0-9A-Fa-f]+$ hex string to preserve precision (§8/§11.1).` });
    } else {
      errors.push({ message: `${ctx}: checksumParams.${key} must be a non-negative integer or a 0x hex string (§8).` });
    }
  }
  // width: 1–64 if present; required when the field type lacks a single
  // declared bit width (bytes/varint/berLength).
  const typeHasDeclaredWidth = field.type.kind === "int" || field.type.kind === "bits" || field.type.kind === "enum";
  if (p.width !== undefined) {
    if (!Number.isInteger(p.width) || p.width < 1 || p.width > 64)
      errors.push({ message: `${ctx}: checksumParams.width must be an integer in 1–64, got ${String(p.width)} (§8).` });
  } else if (!typeHasDeclaredWidth) {
    errors.push({ message: `${ctx}: checksumParams on a field whose type has no single declared bit width (e.g. bytes) requires an explicit width (§8/§11.1).` });
  }
}

/** Decode a mask given as a non-negative integer or a 0x hex string to BigInt (§12, D4). */
function decodeMask(mask: unknown): bigint | undefined {
  if (typeof mask === "number") {
    if (!Number.isInteger(mask) || mask < 0) return undefined;
    return BigInt(mask);
  }
  if (typeof mask === "string" && HEX_PARAM_RE.test(mask)) return BigInt(mask);
  return undefined;
}

/** Subfield keys (schema Subfield, `additionalProperties: false`, §12). */
const SUBFIELD_KEYS: ReadonlySet<string> = new Set([
  "id", "name", "mask", "doc", "values", "level", "category", "meta",
]);

/**
 * §12/§11.1 (D4): validate `subfields`. Permitted only on `int` or a
 * byte-aligned `bits` field (n a multiple of 8). Each `mask` must be a
 * non-negative integer or a 0x hex string and fit within the parent's declared
 * bit width (mask < 2^width), decoded at BigInt precision so masks above 53 bits
 * are exact. Overlap / zero masks are a §11.4 lint, not a hard error.
 */
function validateSubfields(field: Field, ctx: string, errors: ValidationError[]): void {
  const subs = field.subfields!;
  if (!Array.isArray(subs)) {
    errors.push({ message: `${ctx}: subfields must be an array (§12).` });
    return;
  }
  const t = field.type;
  const isInt = t.kind === "int";
  const isByteAlignedBits = t.kind === "bits" && Number.isInteger(t.n) && t.n % 8 === 0;
  if (!isInt && !isByteAlignedBits) {
    errors.push({ message: `${ctx}: subfields are only allowed on an int field or a byte-aligned bits field (n a multiple of 8), §12/§11.1.` });
    return;
  }
  const width = isInt ? (t as { bits: number }).bits : (t as { n: number }).n;
  const limit = 1n << BigInt(width);
  subs.forEach((sf, i) => {
    const tag = `${ctx}: subfields[${i}]`;
    if (typeof sf !== "object" || sf === null) { errors.push({ message: `${tag} must be an object (§12).` }); return; }
    for (const key of Object.keys(sf))
      if (!SUBFIELD_KEYS.has(key))
        errors.push({ message: `${tag} has unknown key "${key}" (allowed: ${[...SUBFIELD_KEYS].join(", ")}) (§12).` });
    if (typeof sf.id !== "string" || !ID_RE.test(sf.id))
      errors.push({ message: `${tag}: id "${String(sf.id)}" must match ${ID_RE} (§12).` });
    if (typeof sf.name !== "string")
      errors.push({ message: `${tag}: name must be a string (§12).` });
    const m = decodeMask(sf.mask);
    if (m === undefined)
      errors.push({ message: `${tag}: mask must be a non-negative integer or a ^0x[0-9A-Fa-f]+$ hex string (§12).` });
    else if (m >= limit)
      errors.push({ message: `${tag}: mask ${String(sf.mask)} does not fit within the field's declared ${width}-bit width (§12/§11.1).` });
    if (sf.level !== undefined && !NORM_LEVELS.has(sf.level as string))
      errors.push({ message: `${tag}: invalid level "${String(sf.level)}" (must be must|should|may) (§12).` });
    if (sf.category !== undefined && !CATEGORY_TOKEN_SET.has(sf.category as string))
      errors.push({ message: `${tag}: category "${String(sf.category)}" is not one of the nine category tokens (§5.1).` });
    if (sf.doc !== undefined && typeof sf.doc !== "string")
      errors.push({ message: `${tag}: doc must be a string (§12).` });
    validateMeta(sf.meta, tag, errors);
  });
}

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
  validateMeta(field.meta, `${ctx}/${field.id}`, w.errors);
  // §5.1/§11.1: `category` is a closed nine-token set. An unknown token (e.g. a
  // typo'd "checsum" or a not-yet-standard token) is a validation error, mirroring
  // the schema's CategoryToken enum so the two validation layers agree.
  if (field.category !== undefined && !CATEGORY_TOKEN_SET.has(field.category))
    w.errors.push({ message: `${ctx}/${field.id}: category "${String(field.category)}" is not one of the nine category tokens (§5.1).` });
  // §8/§11.1: `checksumParams` may only refine a CRC parameter model. Using it
  // with a named non-CRC algorithm (`internet`, `adler32`) is a validation error
  // — these algorithms have fixed internal parameters incompatible with the CRC set.
  if (field.checksumParams !== undefined &&
      field.checksumAlgorithm !== undefined &&
      NON_CRC_CHECKSUM_ALGORITHMS.has(field.checksumAlgorithm))
    w.errors.push({ message: `${ctx}/${field.id}: checksumParams cannot be used with the non-CRC algorithm "${field.checksumAlgorithm}" (§8/§11.1).` });
  if (field.checksumParams !== undefined)
    validateChecksumParams(field, `${ctx}/${field.id}`, w.errors);
  if (field.subfields !== undefined)
    validateSubfields(field, `${ctx}/${field.id}`, w.errors);
  if (field.byteOrder !== undefined && field.byteOrder !== "BE" && field.byteOrder !== "LE")
    w.errors.push({ message: `${ctx}/${field.id}: byteOrder must be 'BE' or 'LE'.` });
  if (field.computedFrom !== undefined) {
    if (field.computedFrom.kind !== "wireSize")
      w.errors.push({ message: `${ctx}/${field.id}: computedFrom must be a wireSize expression.` });
    else
      validateExprPlacement(field.computedFrom, "computedFrom", `${ctx}/${field.id}`, w.errors, w.pc);
  }
  if (field.values !== undefined) {
    if (!Array.isArray(field.values)) {
      w.errors.push({ message: `${ctx}/${field.id}: values must be an array (§5.3).` });
    } else {
      field.values.forEach((ve, i) => {
        const tag = `${ctx}/${field.id}: values[${i}]`;
        // Guard against null/non-object entries (e.g. YAML `values: [~]`):
        // the validator must report, not crash on, untrusted input.
        if (typeof ve !== "object" || ve === null) {
          w.errors.push({ message: `${tag} must be an object (§5.3).` });
          return;
        }
        // Mirrors the schema's ValueEntry `additionalProperties: false` so a
        // typo'd annotation key (e.g. "lable") cannot silently vanish (§5.3).
        for (const key of Object.keys(ve)) {
          if (!VALUE_ENTRY_KEYS.has(key))
            w.errors.push({ message: `${tag} has unknown key "${key}" (allowed: ${[...VALUE_ENTRY_KEYS].join(", ")}) (§5.3).` });
        }
        const hasValue = ve.value !== undefined;
        const hasRange = ve.range !== undefined;
        const hasPattern = ve.pattern !== undefined;
        const forms = (hasValue ? 1 : 0) + (hasRange ? 1 : 0) + (hasPattern ? 1 : 0);
        if (forms !== 1)
          w.errors.push({ message: `${tag} must set exactly one of 'value', 'range', or 'pattern' (§5.3).` });
        // Values may be negative: signed int fields annotate negative codes (§5.3).
        if (hasValue && !Number.isInteger(ve.value))
          w.errors.push({ message: `${tag}: value must be an integer.` });
        if (hasRange) {
          const r = ve.range as unknown;
          if (!Array.isArray(r) || r.length !== 2 ||
              !Number.isInteger(r[0]) || !Number.isInteger(r[1]) ||
              (r[1] as number) < (r[0] as number))
            w.errors.push({ message: `${tag}: range must be [min, max] integers with min ≤ max.` });
        }
        if (hasPattern && (typeof ve.pattern !== "string" || !PATTERN_RE.test(ve.pattern)))
          w.errors.push({ message: `${tag}: pattern must be a non-empty string of 0, 1, or x/X.` });
        // Mirrors the schema's ValueEntry `name`/`label`/`doc` `type: string`
        // so a YAML scalar that parses as a number (e.g. `name: 404`) is
        // rejected by both validation layers (§5.3, §16.4).
        if (ve.name !== undefined && typeof ve.name !== "string")
          w.errors.push({ message: `${tag}: name must be a string (§5.3).` });
        if (ve.label !== undefined && typeof ve.label !== "string")
          w.errors.push({ message: `${tag}: label must be a string (§5.3).` });
        if (ve.doc !== undefined && typeof ve.doc !== "string")
          w.errors.push({ message: `${tag}: doc must be a string (§5.3).` });
        if (ve.level !== undefined && !NORM_LEVELS.has(ve.level))
          w.errors.push({ message: `${tag}: invalid level "${String(ve.level)}" (must be must|should|may).` });
        validateMeta(ve.meta, tag, w.errors);
      });
    }
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
  validateMeta(g.meta, `${ctx}/${g.id}`, w.errors);
  if (!Array.isArray(g.children))
    w.errors.push({ message: `${ctx}: group "${g.id}" must have a children array.` });
  else withOpen(w, g.id, () => {
    for (const child of g.children) validateContainerCtx(child, `${ctx}/${g.id}`, w);
  });
}

function validateRepeat(r: Repeat, ctx: string, w: WalkCtx): void {
  const sub = `${ctx}/${r.id}`;
  // §10.7: a `repeat.count`/`repeat.count.until` ordinary `ref` to a field of
  // this repeat's element resolves to the just-completed iteration's value and
  // is exempt from the §10.1 forward-reference rule. Build the exempt set from
  // the element subtree's referenceable ids (bare + dotted, exactly as a
  // within-element ref would name them). Walking `element.fields` — NOT the
  // repeat container — means this set does NOT include the repeat's own id, so
  // a self-ref to the repeat id (or a forward ref to a non-element sibling)
  // still errors. The set is passed ONLY to the count/until placement calls.
  const elemIds = new Set<string>();
  if (w.pc && r.element && Array.isArray(r.element.fields))
    collectDeclaredIds(r.element.fields, w.defs, "", elemIds, new Set(), 0);
  if (r.count === "eos") {
    /* ok */
  } else if (typeof r.count === "object" && "until" in r.count) {
    // Mirrors schema RepeatCount until-form additionalProperties:false: the
    // count object accepts only the `until` key.
    for (const key of Object.keys(r.count))
      if (key !== "until")
        w.errors.push({ message: `${sub}: repeat count until-object accepts only the "until" key (got "${key}").` });
    if (!isValidExpr(r.count.until)) w.errors.push({ message: `${sub}: repeat until has a malformed expression.` });
    else validateExprPlacement(r.count.until, "repeat.until", sub, w.errors, w.pc, elemIds);
  } else if (!isValidExpr(r.count)) {
    w.errors.push({ message: `${sub}: repeat count has a malformed expression.` });
  } else {
    validateExprPlacement(r.count, "repeat.count", sub, w.errors, w.pc, elemIds);
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
  validateMeta(e.meta, sub, w.errors);
  if (!e.plaintext || !Array.isArray(e.plaintext.fields))
    w.errors.push({ message: `${sub}: encrypted container must have a plaintext struct.` });
  if (e.wireBits !== undefined) {
    if (!isValidExpr(e.wireBits)) w.errors.push({ message: `${sub}: encrypted wireBits is malformed.` });
    else validateExprPlacement(e.wireBits, "wireBits", sub, w.errors, w.pc);
  }
  // §5/§11.1 (D6): every `headerProtected` id must resolve to either (a) a
  // direct leaf field of this encrypted container's plaintext, or (b) a field
  // declared earlier in the SAME body in document order (a plaintext-external
  // header field a header-protection scheme reorders/masks, e.g. QUIC's first
  // byte and packet number). The "earlier same-body" set is exactly the
  // document-order declaredIds tracked so far (w.pc). This is the single
  // normative resolution set shared with normalize (walkEncrypted).
  if (Array.isArray(e.headerProtected) && e.plaintext && Array.isArray(e.plaintext.fields)) {
    const resolvable = new Set<string>();
    for (const c of e.plaintext.fields)
      if (isField(c) && typeof c.id === "string") resolvable.add(c.id);
    if (w.pc !== undefined)
      for (const id of w.pc.declaredIds) resolvable.add(id);
    for (const hp of e.headerProtected) {
      if (typeof hp !== "string" || !resolvable.has(hp))
        w.errors.push({ message: `${sub}: headerProtected id "${String(hp)}" resolves to neither a plaintext field of this encrypted container nor a field declared earlier in the same body (§5/§11.1).` });
    }
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
  validateMeta(b.meta, sub, w.errors);
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
  validateMeta(o.meta, ctx, w.errors);
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
  // declaredExprIds additionally captures the richer subtree set (dotted +
  // bare-tail + local-ref-expanded ids) for the §D11 leaf-ref forward check, in
  // the SAME document-order position. Both registrations happen post-dispatch,
  // so a container's own id is not yet present while its body expressions are
  // validated (self-size ref correctly flagged).
  if (w.pc) {
    const id = containerId(c);
    if (typeof id === "string") w.pc.declaredIds.add(id);
    if (w.pc.declaredExprIds !== undefined)
      collectSubtreeDeclaredIds(c, w.defs, "", w.pc.declaredExprIds, new Set(), 0);
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
  validateMeta(s.meta, `${ctx}/${s.id ?? "?"}`, w.errors);
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
 * §D11: collect every id a body/constraint `ref`/`wireSize` may legally name.
 * This includes: each authored container/field id (bare), each local-ref-
 * expanded dotted id (`{ref.id}.{field.id}`, recursing through local defs with
 * a one-level cap for recursive defs), and — to honour §6 nearest-preceding
 * bare-id resolution — the bare tail segment of every expanded id (so a bare
 * `oct0` referencing an expanded `src.oct0` resolves). Import-qualified ref
 * targets are NOT expanded here; those are deferred to the import layer (§1.2)
 * and detected via `importPrefixes` at the use site.
 */
function collectDeclaredIds(
  containers: Container[],
  defs: Record<string, NamedStruct>,
  prefix: string,
  out: Set<string>,
  seenRefs: ReadonlySet<string>,
  depth: number,
): void {
  if (depth > 64) return;
  for (const c of containers)
    collectSubtreeDeclaredIds(c, defs, prefix, out, seenRefs, depth);
}

/**
 * §D11: emit every body/constraint-referenceable id contributed by a SINGLE
 * container `c` and its subtree (full dotted id + bare tail segment, with local
 * `ref` targets expanded once). Used both up-front to build `documentDeclaredIds`
 * (via collectDeclaredIds) and incrementally — at each container's post-dispatch
 * close point — to build the document-order `declaredExprIds` set the forward-
 * reference check consults. Because the up-front and incremental builders share
 * this helper, the two sets agree on exactly which ids exist; they differ only
 * in WHEN an id appears (incrementally, an id appears only once its container has
 * closed in document order), which is precisely the §10.1 forward-order signal.
 */
function collectSubtreeDeclaredIds(
  c: Container,
  defs: Record<string, NamedStruct>,
  prefix: string,
  out: Set<string>,
  seenRefs: ReadonlySet<string>,
  depth: number,
): void {
  if (depth > 64) return;
  const add = (id: string): void => {
    const full = prefix ? `${prefix}.${id}` : id;
    out.add(full);
    out.add(id); // bare tail segment (nearest-preceding bare-id resolution, §6)
  };
  if (isField(c)) { if (typeof c.id === "string") add(c.id); return; }
  switch (c.kind) {
    case "virtual": if (typeof c.id === "string") add(c.id); break;
    case "group": add(c.id); collectDeclaredIds(c.children, defs, prefix, out, seenRefs, depth); break;
    case "bounded": add(c.id); collectDeclaredIds(c.fields, defs, prefix, out, seenRefs, depth); break;
    case "optional": if (typeof c.id === "string") add(c.id); collectDeclaredIds([c.container], defs, prefix, out, seenRefs, depth); break;
    case "encrypted": add(c.id); collectDeclaredIds(c.plaintext.fields, defs, prefix, out, seenRefs, depth); break;
    case "repeat": add(c.id); collectDeclaredIds(c.element.fields, defs, prefix ? `${prefix}.${c.id}` : c.id, out, seenRefs, depth); break;
    case "switch": add(c.id); for (const arm of Object.values(c.cases)) collectDeclaredIds(arm.fields, defs, prefix, out, seenRefs, depth); break;
    case "align": if (typeof c.id === "string") add(c.id); break;
    case "ref": {
      add(c.id);
      if (c.ref.includes(".")) break; // import-qualified: defer to import layer
      if (seenRefs.has(c.ref)) break; // recursive def: expand once
      const def = defs[c.ref];
      if (!def) break;
      collectDeclaredIds(def.fields, defs, prefix ? `${prefix}.${c.id}` : c.id, out, new Set([...seenRefs, c.ref]), depth + 1);
      break;
    }
  }
}

/* ------------------------------------------------------------------ *
 * Expanded-id collision detection (§2, §11.1)
 * ------------------------------------------------------------------ */

/**
 * A switch-arm selection step: which arm key of which switch a declaration sits
 * under. Two declarations are mutually exclusive (and so may legally share an
 * expanded id) iff their armPaths diverge on the SAME switch id with DIFFERENT
 * arm keys at some common position.
 */
type ArmStep = { switchId: string; key: string };

/** True if the two arm-paths can never be selected simultaneously (§5). */
function mutuallyExclusive(a: ArmStep[], b: ArmStep[]): boolean {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]!.switchId === b[i]!.switchId) {
      if (a[i]!.key !== b[i]!.key) return true;
    } else {
      // Diverged on different switches before any shared discriminating switch:
      // they are not mutually exclusive through this position.
      return false;
    }
  }
  return false;
}

type EidRecord = { armPath: ArmStep[]; ctx: string };

/**
 * §2/§11.1: detect two declarations that would emit the SAME expanded id while
 * both able to be present in the env at once. "Expanded id" here is the id of
 * the emitted NormalizedField: the ref-prefix-joined id (group/optional/bounded/
 * encrypted/align do NOT contribute to the prefix; only `ref` does). The `#N`
 * repeat-index suffix is a runtime instance handle (§6) and is NOT part of this
 * static id; a repeat container instead opens a distinct id namespace (its
 * element-field ids cannot collide with non-repeat siblings), captured by
 * threading the repeat id into the prefix path. Mutually-exclusive switch arms
 * may legally reuse an id (§5); every other same-namespace duplicate — a flat
 * sibling duplicate, a duplicated ref instantiation id, an in-arm duplicate, or
 * an arm-vs-enclosing clash — is a validation error.
 *
 * SCOPE LIMITATION (mirrors detectRefCycles): only local-def `ref` targets are
 * expanded. An import-qualified ref (a `ref` containing `.`) is not expanded
 * here, so collisions inside imported defs are left to the import-resolving
 * layer, which MUST re-run this check over the merged def tree.
 */
function detectExpandedIdCollisions(
  packet: Packet,
  defs: Record<string, NamedStruct>,
  errors: ValidationError[],
): void {
  // eid -> records seen so far. A new record collides with an existing one iff
  // they are NOT mutually exclusive.
  const seen = new Map<string, EidRecord[]>();

  const register = (eid: string, armPath: ArmStep[], ctx: string): void => {
    const prior = seen.get(eid);
    if (prior === undefined) { seen.set(eid, [{ armPath, ctx }]); return; }
    for (const rec of prior) {
      if (!mutuallyExclusive(rec.armPath, armPath)) {
        errors.push({
          message: `expanded id "${eid}" is declared more than once where both declarations can be live at the same time (${rec.ctx} and ${ctx}); ids that share an expanded id must be in mutually-exclusive switch arms (§2/§11.1).`,
        });
        // Still record so further duplicates are reported against this one too.
      }
    }
    prior.push({ armPath, ctx });
  };

  // prefix is the ref/repeat namespace path (joined with "."); armPath tracks
  // switch-arm selection. seenRefs guards recursive defs (expand at most once).
  const walk = (
    containers: Container[],
    prefix: string,
    armPath: ArmStep[],
    ctx: string,
    seenRefs: ReadonlySet<string>,
    depth: number,
  ): void => {
    if (depth > 64) return; // recursive-def boundary (§6/§10.7)
    for (const c of containers) {
      const eidOf = (id: string): string => (prefix ? `${prefix}.${id}` : id);
      if (isField(c)) {
        if (typeof c.id === "string") register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
        continue;
      }
      switch (c.kind) {
        case "virtual":
          if (typeof c.id === "string") register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          break;
        case "group":
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          walk(c.children, prefix, armPath, `${ctx}/${c.id}`, seenRefs, depth);
          break;
        case "bounded":
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          walk(c.fields, prefix, armPath, `${ctx}/${c.id}`, seenRefs, depth);
          break;
        case "optional":
          walk([c.container], prefix, armPath, ctx, seenRefs, depth);
          break;
        case "encrypted":
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          walk(c.plaintext.fields, prefix, armPath, `${ctx}/${c.id}`, seenRefs, depth);
          break;
        case "repeat":
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          // The repeat opens a distinct namespace: its element fields are keyed
          // by the repeat id so they cannot collide with non-repeat siblings,
          // and each iteration is distinguished by the runtime #N suffix.
          walk(c.element.fields, eidOf(c.id), armPath, `${ctx}/${c.id}`, seenRefs, depth);
          break;
        case "switch":
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          for (const [key, arm] of Object.entries(c.cases)) {
            walk(arm.fields, prefix, [...armPath, { switchId: c.id, key }], `${ctx}/${c.id}[${key}]`, seenRefs, depth);
          }
          break;
        case "ref": {
          register(eidOf(c.id), armPath, `${ctx}/${c.id}`);
          // Only expand local-def targets; import-qualified refs are deferred.
          if (c.ref.includes(".")) break;
          if (seenRefs.has(c.ref)) break; // recursive def: expand once
          const def = defs[c.ref];
          if (!def) break;
          walk(def.fields, eidOf(c.id), armPath, `${ctx}/${c.id}`, new Set([...seenRefs, c.ref]), depth + 1);
          break;
        }
        case "align":
          break;
      }
    }
  };

  walk(packet.body ?? [], "", [], packet.name, new Set(), 0);
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
  validateMeta(packet.meta, "packet", errors, PACKET_META_KEYS);

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
  // §2/§11.1: two declarations that emit the same expanded id while both can be
  // live at once (outside mutually-exclusive switch arms) are a validation error.
  detectExpandedIdCollisions(packet, defs, errors);

  // Body — single shared WalkCtx so document-order tracking (§10.1) spans the
  // whole body. The top-level body is a scope provider that carries both a byte
  // budget (`remaining`) and an injected bit budget (`enclosingBits`), §4.
  const repeatIds = new Set<string>();
  collectRepeatIds(packet.body ?? [], repeatIds);
  // §D11: the set of ids a body/constraint ref/wireSize may name, and the
  // import `as` prefixes whose dotted refs are deferred to the import layer.
  const documentDeclaredIds = new Set<string>();
  collectDeclaredIds(packet.body ?? [], defs, "", documentDeclaredIds, new Set(), 0);
  const importPrefixes = new Set<string>(
    (packet.imports ?? [])
      .map((imp) => imp.as)
      .filter((a): a is string => typeof a === "string"),
  );
  const pc: PlacementCtx = {
    remainingOk: true,
    enclosingBitsOk: true,
    declaredIds: new Set<string>(),
    declaredExprIds: new Set<string>(),
    openIds: new Set<string>(),
    repeatIds,
    documentDeclaredIds,
    importPrefixes,
  };
  const bodyW: WalkCtx = { errors, defs, inDef: false, pc };
  for (const c of packet.body ?? []) {
    validateContainerCtx(c, packet.name, bodyW);
  }
  // Defs bodies (virtual forbidden inside)
  for (const [name, def] of Object.entries(defs)) {
    const w: WalkCtx = { errors, defs, inDef: true };
    // §5.4/§6: defs structs may carry meta; validate its shape like every
    // other meta-bearing level (mirrors the schema's NamedStruct).
    validateMeta(def.meta, `defs/${name}`, errors);
    if (!Array.isArray(def.fields)) {
      errors.push({ message: `defs/${name}: struct must have a fields array.` });
      continue;
    }
    for (const child of def.fields) validateContainerCtx(child, `defs/${name}`, w);
  }
  // Constraints
  for (const [i, con] of (packet.constraints ?? []).entries()) {
    // Mirrors the schema's Constraint `additionalProperties: false` so a
    // typo'd key (e.g. "leval" for "level") cannot silently demote a should
    // constraint to the default `must` (§9.1, §16.4).
    for (const key of Object.keys(con)) {
      if (!CONSTRAINT_KEYS.has(key))
        errors.push({ message: `constraints[${i}] has unknown key "${key}" (allowed: ${[...CONSTRAINT_KEYS].join(", ")}) (§9).` });
    }
    // §D11: constraints are exempt from forward-order (§10.1), but ref/wireSize
    // existence is still checked. Pass a pc that carries only the document id
    // set (the forward-order branches are skipped for slot==="constraint").
    const conPc: PlacementCtx = {
      remainingOk: true, enclosingBitsOk: true,
      declaredIds: new Set<string>(), openIds: new Set<string>(), repeatIds,
      documentDeclaredIds, importPrefixes,
    };
    if (!isValidExpr(con.lhs)) errors.push({ message: `constraints[${i}]: malformed lhs.` });
    else validateExprPlacement(con.lhs, "constraint", `constraints[${i}]`, errors, conPc);
    if (!isValidExpr(con.rhs)) errors.push({ message: `constraints[${i}]: malformed rhs.` });
    else validateExprPlacement(con.rhs, "constraint", `constraints[${i}]`, errors, conPc);
    if (con.doc !== undefined && typeof con.doc !== "string")
      errors.push({ message: `constraints[${i}]: doc must be a string (§9).` });
    if (con.level !== undefined && !NORM_LEVELS.has(con.level))
      errors.push({ message: `constraints[${i}]: invalid level "${String(con.level)}" (must be must|should|may).` });
  }
  return errors;
}
