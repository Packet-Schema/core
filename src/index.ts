// @packet-schema/core — public API

// Types
export type {
  Packet,
  PsdlPacket,
  PsdlField,
  PsdlExpr,
  PsdlType,
  Field,
  Repeat,
  Switch,
  Group,
  Encrypted,
  Optional,
  Container,
  Struct,
  Constraint,
  Type,
  TypeInt,
  TypeBits,
  TypeBytes,
  TypeEnum,
  TypeVarint,
  TypeBerLength,
  Expr,
  ExprLit,
  ExprRef,
  ExprOp,
  ExprCond,
  ExprPeek,
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
export { VARINT_ENCODINGS } from "./types.js";

// Expression helpers & evaluator
export {
  lit,
  ref,
  op,
  cond,
  peek,
  peekEnvKey,
  evalExpr,
  exprRefs,
  MissingRefError,
} from "./expr.js";

// Normalize
export { normalize, initialEnv, typeBits, berLenEnvKey } from "./normalize.js";
export type { NormalizeOptions } from "./normalize.js";

// Layout
export { resolveLayout } from "./layout.js";
export type { LayoutOptions } from "./layout.js";

// Constraint solver
export { propagate, validateConstraints } from "./constraint.js";
export type { PropagateResult, PropagateOk, PropagateConflict } from "./constraint.js";

// Validation
export { validatePacket, validateContainer, isValidExpr } from "./validate.js";
export type { ValidationError } from "./validate.js";

// YAML I/O
export { parsePsdl, stringifyPsdl } from "./yaml.js";
export type { ParseResult } from "./yaml.js";

// Utilities
export { isField } from "./utils.js";
export { collectPsdlRefs } from "./collect-refs.js";
