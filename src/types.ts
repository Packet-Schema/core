// PSDL 0.5 — Packet Schema Definition Language
// Canonical type definitions for the PSDL wire format.
//
// Mirrors schemas/psdl-0.5.yaml and spec/psdl-0.5.md. Expressions are pure and
// serialisable (no JS closures on the wire). The core parse model is
// forward-only, relative, and single-packet (§16).

/* ------------------------------------------------------------------ *
 * Categories
 * ------------------------------------------------------------------ */

export type CategoryToken =
  | "addressing"
  | "identifier"
  | "length"
  | "type"
  | "flags"
  | "reserved"
  | "checksum"
  | "variable"
  | "payload-marker";

export const CATEGORY_TOKENS: readonly CategoryToken[] = [
  "addressing", "identifier", "length", "type", "flags",
  "reserved", "checksum", "variable", "payload-marker",
];

/* ------------------------------------------------------------------ *
 * Wire types
 * ------------------------------------------------------------------ */

export type TypeInt = { kind: "int"; bits: number; signed?: boolean };
export type TypeBits = { kind: "bits"; n: number };
/** Variable-length byte array; use `n: { kind: remaining }` for "all remaining" (§3). */
export type TypeBytes = { kind: "bytes"; n: Expr };

export type EnumVariantObj = { label: string; doc?: string };
export type EnumVariant = string | EnumVariantObj;

export type TypeEnum = {
  kind: "enum";
  bits: number;
  /**
   * Variant table keyed by the numeric enum value. NOTE: on the wire / after
   * YAML/JSON parse these keys are *strings* (the schema keys `variants` by
   * stringified non-negative decimal integers such as "6", "17"); the `number`
   * index signature is a convenience — TS coerces numeric indexing to strings.
   */
  variants: Record<number, EnumVariant>;
};

/** Predefined varint encodings; arbitrary strings are also accepted (§3). */
export const VARINT_ENCODINGS = [
  "quic", "protobuf", "cbor", "ea-terminated", "leb128",
] as const;
export type VarintEncoding = string;

export type TypeVarint = { kind: "varint"; encoding: VarintEncoding };

/** BER length field; maxBytes caps the encoded width (1–5, default 5). */
export type TypeBerLength = { kind: "berLength"; maxBytes?: number };

export type Type =
  | TypeInt
  | TypeBits
  | TypeBytes
  | TypeEnum
  | TypeVarint
  | TypeBerLength;

/* ------------------------------------------------------------------ *
 * Expressions
 * ------------------------------------------------------------------ */

export type BinOp =
  | "+" | "-" | "*" | "/" | "%" | "<<" | ">>"
  | "==" | "!=" | "<" | "<=" | ">" | ">="
  | "&" | "|" | "^";

export const BIN_OPS: readonly BinOp[] = [
  "+", "-", "*", "/", "%", "<<", ">>",
  "==", "!=", "<", "<=", ">", ">=",
  "&", "|", "^",
];

export type ExprLit = { kind: "lit"; value: number };
export type ExprRef = { kind: "ref"; field: string };
export type ExprOp = { kind: "op"; op: BinOp; a: Expr; b: Expr };
export type ExprCond = { kind: "cond"; test: Expr; t: Expr; f: Expr };
/** Look ahead without advancing the cursor (§10.6). `bits` is 1–64. */
export type ExprPeek = { kind: "peek"; bits: number; offset?: Expr };
/**
 * Discrete table lookup; missing key → 0 (§4). NOTE: as with enum variants,
 * `table` keys are stringified non-negative decimal integers on the wire (the
 * schema constrains `propertyNames` to `^(0|[1-9][0-9]*)$`); the `number` index
 * signature is a convenience that TS coerces to string keys at runtime.
 */
export type ExprLookup = { kind: "lookup"; key: Expr; table: Record<number, number> };
/** Wire byte footprint of a named container/field (§4). */
export type ExprWireSize = { kind: "wireSize"; target: string };
/** Value of a field from the previous completed repeat iteration (§4, §10.4). */
export type ExprPrevIter = { kind: "prevIter"; field: string };
/** Bytes remaining in the enclosing scope-providing container (§4). */
export type ExprRemaining = { kind: "remaining" };
/** Bit budget of the nearest scope-providing container that carries one (§4). */
export type ExprEnclosingBits = { kind: "enclosingBits" };
/** Cross-layer field access; constraints only (§7). */
export type ExprEnclosingField = { kind: "enclosingField"; field: string };

export type Expr =
  | ExprLit
  | ExprRef
  | ExprOp
  | ExprCond
  | ExprPeek
  | ExprLookup
  | ExprWireSize
  | ExprPrevIter
  | ExprRemaining
  | ExprEnclosingBits
  | ExprEnclosingField;

/* ------------------------------------------------------------------ *
 * Checksum
 * ------------------------------------------------------------------ */

/** Well-known algorithms; arbitrary strings are accepted (§8). */
export const CHECKSUM_ALGORITHMS = [
  "internet", "crc32", "crc32c", "crc16", "adler32",
] as const;
export type ChecksumAlgorithm = string;

export type ChecksumParams = {
  polynomial?: number;
  initValue?: number;
  finalXOR?: number;
  inputReflect?: boolean;
  outputReflect?: boolean;
};

export type PseudoHeader = "ipv4" | "ipv6";

/* ------------------------------------------------------------------ *
 * Display / metadata
 * ------------------------------------------------------------------ */

export type DisplayHint = "dec" | "hex" | "oct" | "bin" | "ascii" | "utf8" | "addr";

/** Per-field / per-region RFC annotation (§5). */
export type FieldMeta = { rfc?: number; section?: string };

/* ------------------------------------------------------------------ *
 * Containers
 * ------------------------------------------------------------------ */

export type Field = {
  kind?: "field";
  id: string;
  name: string;
  type: Type;
  doc?: string;
  meta?: FieldMeta;
  category?: CategoryToken;
  defaultValue?: number;
  byteOrder?: "BE" | "LE";
  next?: Record<string, string>;
  checksumAlgorithm?: ChecksumAlgorithm;
  checksumCovers?: string[];
  checksumPseudoHeader?: PseudoHeader;
  checksumParams?: ChecksumParams;
  const?: number;
  display?: DisplayHint;
  /** Serializer hint; must be a wireSize expression (§4, §6). */
  computedFrom?: ExprWireSize;
};

/** Computed auxiliary field; consumes zero wire bytes (§5). */
export type Virtual = {
  kind: "virtual";
  id: string;
  expr: Expr;
  name?: string;
  doc?: string;
};

/** Nested optionals are allowed; inner `when` is short-circuited (§10.8). */
export type Optional = {
  kind: "optional";
  id?: string;
  when: Expr;
  container: Container;
  doc?: string;
  meta?: FieldMeta;
};

/** Anonymous struct used as Repeat.element / Switch arm / Encrypted.plaintext. */
export type Struct = {
  id: string;
  doc?: string;
  meta?: FieldMeta;
  fields: Container[];
};

/** Struct type used exclusively as a `defs` value; may be recursive (§6). */
export type NamedStruct = {
  id: string;
  doc?: string;
  recursive?: boolean;
  fields: Container[];
};

export type Group = {
  kind: "group";
  id: string;
  name: string;
  doc?: string;
  meta?: FieldMeta;
  category?: CategoryToken;
  children: Container[];
};

export type RepeatCount = Expr | "eos" | { until: Expr };

export type Repeat = {
  kind: "repeat";
  id: string;
  name?: string;
  element: Struct;
  count: RepeatCount;
  category?: CategoryToken;
  doc?: string;
};

export type Switch = {
  kind: "switch";
  id: string;
  name?: string;
  on: Expr;
  cases: Record<string, Struct>;
  doc?: string;
};

export type Encrypted = {
  kind: "encrypted";
  id: string;
  name?: string;
  plaintext: Struct;
  wireBits?: Expr;
  contextNote?: string;
  headerProtected?: string[];
  category?: CategoryToken;
  doc?: string;
};

export type RefContainer = {
  kind: "ref";
  ref: string;
  id: string;
  name?: string;
};

/** Aligns the parse cursor to a bit boundary measured from the wire origin (§5). */
export type Align = {
  kind: "align";
  /** Boundary in bits; must be a positive power of 2 that is a multiple of 8. */
  to: number;
  /** Padding byte value, 0–255 (default 0). */
  fill?: number;
  id?: string;
  doc?: string;
};

/** Constrains parsing of its contents to a declared byte count (§5). */
export type Bounded = {
  kind: "bounded";
  id: string;
  bytes: Expr;
  fields: Container[];
  name?: string;
  doc?: string;
};

export type Container =
  | Field
  | Virtual
  | Group
  | Optional
  | Repeat
  | Switch
  | Align
  | Bounded
  | Encrypted
  | RefContainer;

/* ------------------------------------------------------------------ *
 * Constraints
 * ------------------------------------------------------------------ */

export type Constraint = {
  lhs: Expr;
  rhs: Expr;
  doc?: string;
};

/* ------------------------------------------------------------------ *
 * Packet-level metadata
 * ------------------------------------------------------------------ */

export type PacketMeta = {
  rfc?: number;
  section?: string;
  aliases?: string[];
};

export type ImportEntry = {
  source: string;
  as: string;
};

export type RendererSection = {
  id: string;
  label: string;
  fields: string[];
};

export type RendererHints = {
  rowBits?: number;
  sections?: RendererSection[];
};

/* ------------------------------------------------------------------ *
 * Packet
 * ------------------------------------------------------------------ */

export type Packet = {
  version?: string;
  name: string;
  /** @deprecated use rendererHints.rowBits */
  rowBits?: number;
  abbrev?: string;
  body: Container[];
  constraints?: Constraint[];
  byteOrder?: "BE" | "LE";
  description?: string;
  rendererHints?: RendererHints;
  meta?: PacketMeta;
  defs?: Record<string, NamedStruct>;
  imports?: ImportEntry[];
};

export type PsdlPacket = Packet;
export type PsdlField = Field;
export type PsdlExpr = Expr;
export type PsdlType = Type;

/* ------------------------------------------------------------------ *
 * Normalized output
 * ------------------------------------------------------------------ */

export type NormalizedField = {
  id: string;
  name: string;
  bits: number;
  absoluteBitOffset: number;
  originalContainerPath: string;
  category?: CategoryToken;
  doc?: string;
  repeatIndex?: number;
  switchCase?: string;
  encrypted?: boolean;
  encryptedParentId?: string;
  encryptedContextNote?: string;
  headerProtected?: boolean;
  byteOrder?: "BE" | "LE";
  groupId?: string;
  groupName?: string;
  /** Virtual (zero-width computed) field marker. */
  virtual?: boolean;
};

export type Normalized = {
  fields: NormalizedField[];
  totalBits: number;
};

export type PacketEnv = Map<string, number>;

export type ViewMode = "wire" | "semantic";

/* ------------------------------------------------------------------ *
 * Layout output (Cell grid)
 * ------------------------------------------------------------------ */

export type LayoutSubField = {
  id: string;
  name: string;
  bits: number;
  description?: string;
};

export type LayoutField = {
  id: string;
  name: string;
  bits: number;
  category?: CategoryToken;
  description?: string;
  subfields?: LayoutSubField[];
};

export type SubCell = {
  parentField: LayoutField;
  subfield: LayoutSubField;
  id: string;
  startBit: number;
  endBit: number;
  isFirst: boolean;
  isLast: boolean;
  bitsTotal: number;
  encrypted?: boolean;
  encryptedParentId?: string;
  encryptedContextNote?: string;
  headerProtected?: boolean;
  byteOrder?: "BE" | "LE";
};

export type Cell = {
  field: LayoutField;
  bitsTotal: number;
  row: number;
  startBit: number;
  endBit: number;
  segmentIndex: number;
  totalSegments: number;
  isFirst: boolean;
  isLast: boolean;
  fieldStartOffset: number;
  fieldEndOffset: number;
  subCells?: SubCell[];
  encrypted?: boolean;
  encryptedParentId?: string;
  encryptedContextNote?: string;
  headerProtected?: boolean;
  byteOrder?: "BE" | "LE";
};

export type ResolvedLayout = {
  cells: Cell[];
  totalBits: number;
};
