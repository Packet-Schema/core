// @packet-schema/core — public API

// Types
export type {
  Packet,
  PsdlPacket,
  PsdlField,
  PsdlExpr,
  PsdlType,
  Field,
  Virtual,
  Repeat,
  RepeatCount,
  Switch,
  Group,
  Encrypted,
  Optional,
  Align,
  Bounded,
  RefContainer,
  Container,
  Struct,
  NamedStruct,
  Constraint,
  Type,
  TypeInt,
  TypeBits,
  TypeBytes,
  TypeEnum,
  TypeVarint,
  TypeBerLength,
  BytesDelimited,
  VarintEncoding,
  EnumVariant,
  EnumVariantObj,
  Subfield,
  NormativeLevel,
  RfcRef,
  UpdateRef,
  ValueEntry,
  ChecksumAlgorithm,
  ChecksumParams,
  PseudoHeader,
  DisplayHint,
  FieldMeta,
  PacketMeta,
  ImportEntry,
  RendererHints,
  RendererSection,
  Expr,
  ExprLit,
  ExprRef,
  ExprOp,
  ExprCond,
  ExprPeek,
  ExprLookup,
  ExprWireSize,
  ExprPrevIter,
  ExprRemaining,
  ExprEnclosingBits,
  ExprEnclosingField,
  BinOp,
  CategoryToken,
  PacketEnv,
  ViewMode,
  Normalized,
  NormalizedField,
  LayoutField,
  LayoutSubField,
  Cell,
  SubCell,
  ResolvedLayout,
} from "./types.js";
export {
  VARINT_ENCODINGS,
  CHECKSUM_ALGORITHMS,
  CATEGORY_TOKENS,
  BIN_OPS,
} from "./types.js";

// Expression helpers & evaluator
export {
  lit,
  ref,
  op,
  cond,
  peek,
  lookup,
  wireSize,
  prevIter,
  remaining,
  enclosingBits,
  enclosingField,
  peekEnvKey,
  remainingEnvKey,
  enclosingBitsEnvKey,
  wireSizeEnvKey,
  prevIterEnvKey,
  enclosingFieldEnvKey,
  evalExpr,
  evalExprOr,
  exprRefs,
  walkExpr,
  exprContains,
  MissingRefError,
} from "./expr.js";

// Normalize
export {
  normalize,
  initialEnv,
  typeBits,
  berLenEnvKey,
  varintBitsEnvKey,
  bytesDelimLenEnvKey,
  isBytesDelimited,
  selectArm,
} from "./normalize.js";
export type { NormalizeOptions } from "./normalize.js";

// Layout
export { resolveLayout } from "./layout.js";
export type { LayoutOptions } from "./layout.js";

// Constraint solver
export {
  propagate,
  propagateFixpoint,
  validateConstraints,
} from "./constraint.js";
export type {
  PropagateResult,
  PropagateOk,
  PropagateConflict,
  ConstraintDiagnostic,
} from "./constraint.js";

// Validation
export { validatePacket, validateContainer, isValidExpr } from "./validate.js";
export type { ValidationError } from "./validate.js";

// Lint (§11.4) — advisory, separate from the hard errors above.
export { lintPacket } from "./lint.js";
export type { LintWarning, LintRule } from "./lint.js";

// YAML I/O
export { parsePsdl, stringifyPsdl } from "./yaml.js";
export type { ParseResult } from "./yaml.js";

// Utilities
export { isField } from "./utils.js";
export { collectPsdlRefs } from "./collect-refs.js";
export { resolveValueEntry, matchesPattern } from "./values.js";
