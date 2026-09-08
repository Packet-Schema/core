import type { BinOp, Expr, ExprWireSize, PacketEnv } from "./types.js";

/* ------------------------------------------------------------------ *
 * Expression constructors (authoring helpers)
 * ------------------------------------------------------------------ */

export const lit = (value: number): Expr => ({ kind: "lit", value });
export const ref = (field: string): Expr => ({ kind: "ref", field });
export const op = (o: BinOp, a: Expr, b: Expr): Expr => ({
  kind: "op",
  op: o,
  a,
  b,
});
export const cond = (test: Expr, t: Expr, f: Expr): Expr => ({
  kind: "cond",
  test,
  t,
  f,
});
export const peek = (bits: number, offset?: Expr): Expr =>
  offset === undefined
    ? { kind: "peek", bits }
    : { kind: "peek", bits, offset };
export const lookup = (key: Expr, table: Record<number, number>): Expr => ({
  kind: "lookup",
  key,
  table,
});
export const wireSize = (target: string): ExprWireSize => ({
  kind: "wireSize",
  target,
});
export const prevIter = (field: string): Expr => ({ kind: "prevIter", field });
export const remaining = (): Expr => ({ kind: "remaining" });
export const enclosingBits = (): Expr => ({ kind: "enclosingBits" });
export const enclosingField = (field: string): Expr => ({
  kind: "enclosingField",
  field,
});

/* ------------------------------------------------------------------ *
 * Reserved env keys for context-dependent expressions.
 * normalize injects these so evalExpr stays pure (§4, §10).
 * ------------------------------------------------------------------ */

export const peekEnvKey = (offset: number, bits: number): string =>
  `__peek__${offset}__${bits}`;
export const remainingEnvKey = (): string => "__remaining__";
export const enclosingBitsEnvKey = (): string => "__enclosingBits__";
export const wireSizeEnvKey = (target: string): string =>
  `__wireSize__${target}`;
export const prevIterEnvKey = (field: string): string => `__prevIter__${field}`;
export const enclosingFieldEnvKey = (field: string): string =>
  `__enclosing__${field}`;

export class MissingRefError extends Error {
  constructor(public readonly field: string) {
    super(`evalExpr: missing reference "${field}"`);
    this.name = "MissingRefError";
  }
}

/* ------------------------------------------------------------------ *
 * Evaluator
 * ------------------------------------------------------------------ */

export function evalExpr(expr: Expr, env: PacketEnv): number {
  switch (expr.kind) {
    case "lit":
      return expr.value;
    case "ref": {
      const v = env.get(expr.field);
      if (v === undefined) throw new MissingRefError(expr.field);
      return v;
    }
    case "op": {
      const a = evalExpr(expr.a, env);
      const b = evalExpr(expr.b, env);
      switch (expr.op) {
        case "+":
          return a + b;
        case "-":
          return a - b;
        case "*":
          return a * b;
        case "/":
          if (b === 0) throw new Error("evalExpr: division by zero");
          return Math.trunc(a / b);
        case "%":
          if (b === 0) throw new Error("evalExpr: modulo by zero");
          // §4 pairs `%` with truncated-division `/` ("truncates toward zero"),
          // so `%` follows JS remainder semantics: the result takes the sign of
          // the dividend (e.g. (1-3) % 4 === -2, NOT the Euclidean 2). The spec
          // does not define a Euclidean modulo; authors must not assume one.
          // Spec keys/table values are non-negative, so a negative left operand
          // here reflects authored arithmetic, not a normalization choice.
          return a % b;
        // Left shift masked to an unsigned 32-bit result (§4): JS `<<` is
        // signed, so a high-bit shift like `1 << 31` would yield a negative
        // number; `>>> 0` reinterprets it as the unsigned wire value.
        case "<<":
          return (a << b) >>> 0;
        // Arithmetic (sign-propagating) right shift, per §4 "Arithmetic right
        // shift; operates on 32-bit integers."
        case ">>":
          return a >> b;
        case "==":
          return a === b ? 1 : 0;
        case "!=":
          return a !== b ? 1 : 0;
        case "<":
          return a < b ? 1 : 0;
        case "<=":
          return a <= b ? 1 : 0;
        case ">":
          return a > b ? 1 : 0;
        case ">=":
          return a >= b ? 1 : 0;
        // §4 (Note on 64-bit fields): bitwise and shift operators are evaluated
        // as 32-bit integers BY DESIGN — JS `&|^` coerce operands via ToInt32,
        // so a value wider than 32 bits is truncated and a high bit may flip the
        // sign. This is the documented spec contract: for fields wider than 32
        // bits, authors must use arithmetic operators and `cond`, not bit ops.
        case "&":
          return (a & b) | 0;
        case "|":
          return a | b | 0;
        case "^":
          return (a ^ b) | 0;
        default: {
          const bad = expr.op as string;
          throw new Error(`evalExpr: unknown operator "${bad}"`);
        }
      }
    }
    case "cond": {
      const t = evalExpr(expr.test, env);
      return t !== 0 ? evalExpr(expr.t, env) : evalExpr(expr.f, env);
    }
    case "peek": {
      const offsetVal =
        expr.offset !== undefined ? evalExpr(expr.offset, env) : 0;
      return env.get(peekEnvKey(offsetVal, expr.bits)) ?? 0;
    }
    case "lookup": {
      // key truncated toward zero; negative or missing key → 0 (§4)
      const k = Math.trunc(evalExpr(expr.key, env));
      const v = expr.table[k];
      return v ?? 0;
    }
    case "wireSize":
      return env.get(wireSizeEnvKey(expr.target)) ?? 0;
    case "prevIter":
      return env.get(prevIterEnvKey(expr.field)) ?? 0;
    case "remaining":
      return env.get(remainingEnvKey()) ?? 0;
    case "enclosingBits":
      return env.get(enclosingBitsEnvKey()) ?? 0;
    case "enclosingField":
      return env.get(enclosingFieldEnvKey(expr.field)) ?? 0;
    default: {
      const _exhaustive: never = expr;
      throw new Error(
        `evalExpr: unknown expression kind "${(_exhaustive as { kind: string }).kind}"`,
      );
    }
  }
}

/** Evaluate, returning `fallback` when a referenced field is missing (§10.3). */
export function evalExprOr(expr: Expr, env: PacketEnv, fallback = 0): number {
  try {
    return evalExpr(expr, env);
  } catch (e) {
    if (e instanceof MissingRefError) return fallback;
    throw e;
  }
}

/* ------------------------------------------------------------------ *
 * Static reference collection
 * ------------------------------------------------------------------ */

/** Plain field-id references (`ref`) reachable from an expression. */
export function exprRefs(expr: Expr): string[] {
  const out: string[] = [];
  walkExpr(expr, (e) => {
    if (e.kind === "ref") out.push(e.field);
  });
  return out;
}

/** Visit every sub-expression node depth-first. */
export function walkExpr(expr: Expr, visit: (e: Expr) => void): void {
  visit(expr);
  switch (expr.kind) {
    case "lit":
    case "ref":
    case "wireSize":
    case "prevIter":
    case "remaining":
    case "enclosingBits":
    case "enclosingField":
      return;
    case "op":
      walkExpr(expr.a, visit);
      walkExpr(expr.b, visit);
      return;
    case "cond":
      walkExpr(expr.test, visit);
      walkExpr(expr.t, visit);
      walkExpr(expr.f, visit);
      return;
    case "peek":
      if (expr.offset !== undefined) walkExpr(expr.offset, visit);
      return;
    case "lookup":
      walkExpr(expr.key, visit);
      return;
    default: {
      const _exhaustive: never = expr;
      throw new Error(
        `walkExpr: unhandled Expr kind ${String((_exhaustive as { kind?: string }).kind)}`,
      );
    }
  }
}

/** True if any sub-expression matches the predicate. */
export function exprContains(expr: Expr, pred: (e: Expr) => boolean): boolean {
  let found = false;
  walkExpr(expr, (e) => {
    if (pred(e)) found = true;
  });
  return found;
}
