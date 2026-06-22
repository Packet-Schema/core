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
/**
 * Delimiter-terminated byte length (§3, D3). The field spans from the current
 * parse position up to and including the first complete occurrence of the
 * delimiter byte sequence; the delimiter is always consumed and is part of the
 * field's wire footprint (and of any `display` rendering). `delimiter` is a
 * non-empty list of byte integers (each 0–255). Length is decoder-determined
 * and supplied by seed injection under a dedicated key (§10.7), forward-only and
 * relative. This `delimiter` form is unrelated to the `repeat.count.until`
 * after-iteration predicate (§5); they share no keyword.
 */
export type BytesDelimited = { delimiter: number[] };
/** Variable-length byte array; use `n: { kind: remaining }` for "all remaining" (§3). */
export type TypeBytes = { kind: "bytes"; n: Expr | BytesDelimited };

export type EnumVariantObj = { label: string; doc?: string; level?: NormativeLevel; meta?: FieldMeta };
export type EnumVariant = string | EnumVariantObj;

/**
 * Open value-dictionary entry (§5.3). Annotates a single discrete value or an
 * inclusive range with meaning, normative strength, and provenance.
 * Purely annotational: it does NOT close the value space (out-of-list values
 * remain valid) and carries no wire semantics.
 */
export type ValueEntry = {
  /** Single value. Mutually exclusive with `range` and `pattern`. */
  value?: number;
  /** Inclusive [min, max] range. Mutually exclusive with `value` and `pattern`. */
  range?: [number, number];
  /**
   * Ternary bit-pattern predicate (§5.3): a string of `0`, `1`, and `x`
   * (don't-care), read like a binary literal — the rightmost character is bit 0
   * (LSB). Matches when every non-`x` bit equals the observed bit. Expresses
   * non-contiguous pools a `range` cannot, e.g. the DSCP experimental pool
   * `"xxxx11"`. Mutually exclusive with `value`/`range`. Contradictions are
   * unrepresentable by construction (every character is 0, 1, or x).
   */
  pattern?: string;
  /** Short machine-style symbol, e.g. "EF", "Not-ECT". */
  name?: string;
  /** Human-readable label, e.g. "Expedited Forwarding". */
  label?: string;
  doc?: string;
  /** Normative strength of this value (RFC 2119). Absent ≡ "may". */
  level?: NormativeLevel;
  meta?: FieldMeta;
};

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

/**
 * CRC parameter overrides (§8). Only valid alongside a `checksumAlgorithm` that
 * uses the CRC parameter model; pairing it with a named non-CRC algorithm
 * (`internet`, `adler32`) is a validation error (§11.1).
 */
export type ChecksumParams = {
  /**
   * Generator polynomial. A bare integer for values ≤ 2^53−1; values that need
   * more than 53 bits MUST be written as a `^0x[0-9A-Fa-f]+$` hex string so the
   * full 64-bit precision survives (a bare integer would lose precision, §8).
   */
  polynomial?: number | string;
  initValue?: number | string;
  finalXOR?: number | string;
  inputReflect?: boolean;
  outputReflect?: boolean;
  /**
   * CRC width in bits (1–64). Optional; when absent the CRC width equals the
   * checksum value field's declared bit width (int.bits / bits.n). Required when
   * the checksum field's type does not have a single declared bit width (e.g. a
   * `bytes` field), §8.
   */
  width?: number;
};

export type PseudoHeader = "ipv4" | "ipv6";

/* ------------------------------------------------------------------ *
 * Display / metadata
 * ------------------------------------------------------------------ */

export type DisplayHint = "dec" | "hex" | "oct" | "bin" | "ascii" | "utf8" | "addr";

/**
 * RFC 2119 normative strength. The default when absent is context-dependent:
 * "must" on a Constraint (legacy fixed behaviour, §9.1), but "may" on a value
 * dictionary entry / enum variant (§5.3) since those are annotations, not rules.
 */
export type NormativeLevel = "must" | "should" | "may";

/**
 * A single updating-RFC reference (§5.4). Either a bare RFC number (≡ `{ rfc: N }`
 * with no section) or an object carrying the updating RFC number plus the section
 * of THAT updating RFC. The defining RFC's own section is carried separately by
 * the sibling `meta.section`.
 */
export type UpdateRef = number | { rfc: number; section?: string };

/**
 * Multi-layer RFC provenance (§5.4). Either a bare RFC number (legacy 0.5 form)
 * or an object recording the defining RFC plus the chain of RFCs that updated
 * the field's layout or semantics. LSP renders "defined by N, updated by …".
 * Each `updates` entry may be a bare number or `{ rfc, section? }`.
 */
export type RfcRef = number | { defined: number; updates?: UpdateRef[] };

/** Per-field / per-region RFC annotation (§5.4). */
export type FieldMeta = { rfc?: RfcRef; section?: string };

/* ------------------------------------------------------------------ *
 * Containers
 * ------------------------------------------------------------------ */

/**
 * Author-facing bit-field annotation over a parent `int`/byte-aligned-`bits`
 * field (§12, D4). A subfield decodes a slice of the parent's BYTE-ORDER-RESOLVED
 * integer value: its value is `(fieldValue & mask) >> lowestSetBit(mask)`, with
 * bit 0 = the least-significant bit (identical to ValueEntry.pattern's bit-0=LSB
 * convention, §5.3). Because the convention is defined over the *decoded value*,
 * it is byte-order-independent and works identically for LE and BE words — which
 * is precisely why it succeeds where a naive MSB-first bits-group fails for
 * little-endian words (802.15.4 / 802.11 / CAN). Subfields are display/annotation
 * only: they consume no wire bits, add no parse semantics, do not appear in
 * `env`, and do not affect `checksumCovers`, expressions, or scoping.
 *
 * RENDER POSITION (this version): subfields carry value-decode semantics for
 * LSP/codegen. A renderer MAY derive sub-cell wire positions from the masks, but
 * exact wire-render placement (especially the non-contiguous LE case) is **not
 * guaranteed by 0.5** and is a candidate for a follow-up revision (§12).
 *
 * `mask` is a non-negative integer; a hex string is permitted for masks needing
 * more than 53 bits (the D9 precedent), and tools MUST decode such masks at full
 * 64-bit precision.
 */
export type Subfield = {
  id: string;
  name: string;
  mask: number | string;
  doc?: string;
  values?: readonly ValueEntry[];
  level?: NormativeLevel;
  category?: CategoryToken;
  meta?: FieldMeta;
};

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
  /** Open value dictionary for discrete values of this field (§5.3). */
  values?: readonly ValueEntry[];
  /** Serializer hint; must be a wireSize expression (§4, §6). */
  computedFrom?: ExprWireSize;
  /**
   * Mask-addressed bit subfields over this `int` / byte-aligned `bits` field
   * (§12, D4). Display/annotation only; value bit 0 = LSB of the decoded value.
   */
  subfields?: readonly Subfield[];
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
  /**
   * RFC provenance for the def as a whole (§5.4, §6). Documentation-grade:
   * available through the source AST only — a `ref` expansion is transparent
   * and emits no container field, so this meta does not appear in the
   * normalized/layout output.
   */
  meta?: FieldMeta;
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
  /** RFC provenance for the encrypted region (§5.4). */
  meta?: FieldMeta;
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
  /** RFC provenance for the bounded region (§5.4). */
  meta?: FieldMeta;
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
  /**
   * Normative strength (§9). Absent ≡ "must". Only `must` constraints (and
   * those with no level) participate in solver back-propagation; `should`/`may`
   * are diagnostic-only (§9.1).
   */
  level?: NormativeLevel;
};

/* ------------------------------------------------------------------ *
 * Packet-level metadata
 * ------------------------------------------------------------------ */

export type PacketMeta = {
  rfc?: RfcRef;
  section?: string;
  aliases?: string[];
  /**
   * Free-form classification tags for catalog/registry grouping and search
   * (§1.1). Multi-axis (layer, function, transport, …); the spec deliberately
   * does NOT constrain the vocabulary — a controlled term list, if any, is
   * governed by the catalog/tooling layer, not the language. Like `aliases`,
   * these are open strings, unlike the closed field-level `category` tokens.
   */
  tags?: string[];
  /**
   * Optional single grouping key for a family of related packet types
   * (e.g. `bgp` for the several BGP message documents). Free-form (§1.1).
   */
  family?: string;
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
  /** RFC provenance of the enclosing group, for per-group LSP deep-linking (§5.4). */
  groupMeta?: FieldMeta;
  /** Virtual (zero-width computed) field marker. */
  virtual?: boolean;
  /** Value dictionary copied verbatim from the source Field (§5.3). */
  values?: readonly ValueEntry[];
  /** RFC provenance copied verbatim from the source Field (§5.4). */
  meta?: FieldMeta;
  /** Mask-addressed bit subfields copied verbatim from the source Field (§12, D4). */
  subfields?: readonly Subfield[];
  /** Checksum algorithm copied verbatim from the source Field, for codegen (§8). */
  checksumAlgorithm?: ChecksumAlgorithm;
  /** Covered field ids copied verbatim from the source Field (§8). */
  checksumCovers?: string[];
  /** Pseudo-header copied verbatim from the source Field (§8). */
  checksumPseudoHeader?: PseudoHeader;
  /** CRC parameter overrides copied verbatim from the source Field (§8). */
  checksumParams?: ChecksumParams;
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
  values?: readonly ValueEntry[];
  meta?: FieldMeta;
};

export type LayoutField = {
  id: string;
  name: string;
  bits: number;
  category?: CategoryToken;
  description?: string;
  values?: readonly ValueEntry[];
  meta?: FieldMeta;
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
