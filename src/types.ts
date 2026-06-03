// PSDL 0.5 — Packet Schema Definition Language
// Canonical type definitions for the PSDL wire format.
//
// Three composition primitives: Repeat, Switch, Group.
// Fields carry semantic category tokens; color is renderer-side.
// Expressions are pure and serialisable — no JS closures on the wire.

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

/* ------------------------------------------------------------------ *
 * Types
 * ------------------------------------------------------------------ */

export type TypeInt = { kind: "int"; bits: number; signed?: boolean };
export type TypeBits = { kind: "bits"; n: number };
export type TypeBytes = { kind: "bytes"; n: Expr };
export type TypeEnum = {
  kind: "enum";
  bits: number;
  variants: Record<number, string>;
};

export type TypeVarint = {
  kind: "varint";
  encoding: "quic" | "protobuf" | "cbor";
};

export const VARINT_ENCODINGS = ["quic", "protobuf", "cbor"] as const;
export type VarintEncoding = (typeof VARINT_ENCODINGS)[number];

export type TypeBerLength = { kind: "berLength" };

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

export type BinOp = "+" | "-" | "*" | "/" | "%" | "<<" | ">>";

export type ExprLit = { kind: "lit"; value: number };
export type ExprRef = { kind: "ref"; field: string };
export type ExprOp = { kind: "op"; op: BinOp; a: Expr; b: Expr };
export type ExprCond = { kind: "cond"; test: Expr; t: Expr; f: Expr };
export type ExprPeek = { kind: "peek"; bits: number; offset?: Expr };

export type Expr = ExprLit | ExprRef | ExprOp | ExprCond | ExprPeek;

/* ------------------------------------------------------------------ *
 * Schema nodes
 * ------------------------------------------------------------------ */

export type Field = {
  kind?: "field";
  id: string;
  name: string;
  type: Type;
  doc?: string;
  category?: CategoryToken;
  defaultValue?: number;
  byteOrder?: "BE" | "LE";
};

export type Optional = {
  kind: "optional";
  id?: string;
  when: Expr;
  field: Field;
};

export type Struct = {
  id: string;
  name?: string;
  fields: Container[];
};

export type Repeat = {
  kind: "repeat";
  id: string;
  name?: string;
  element: Struct;
  count: Expr | "eos" | { until: Expr };
  category?: CategoryToken;
  doc?: string;
};

export type Switch = {
  kind: "switch";
  id: string;
  name?: string;
  on: Expr;
  cases: Record<string, Struct>;
  default?: Struct;
  doc?: string;
};

export type Group = {
  kind: "group";
  id: string;
  name?: string;
  children: Container[];
};

export type Encrypted = {
  kind: "encrypted";
  id: string;
  name?: string;
  plaintext: Struct;
  wireBits?: Expr;
  contextNote: string;
  headerProtected?: string[];
  category?: CategoryToken;
  doc?: string;
};

export type Container = Field | Repeat | Switch | Group | Encrypted | Optional;

/* ------------------------------------------------------------------ *
 * Constraints
 * ------------------------------------------------------------------ */

export type Constraint = {
  lhs: Expr;
  rhs: Expr;
  doc?: string;
};

/* ------------------------------------------------------------------ *
 * Packet
 * ------------------------------------------------------------------ */

export type Packet = {
  version?: string;
  name: string;
  rowBits: number;
  body: Container[];
  constraints?: Constraint[];
  byteOrder?: "BE" | "LE";
  description?: string;
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
