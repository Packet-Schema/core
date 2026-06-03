import type { Expr, PacketEnv } from "./types.js";

export const lit = (value: number): Expr => ({ kind: "lit", value });
export const ref = (field: string): Expr => ({ kind: "ref", field });
export const op = (
  o: "+" | "-" | "*" | "/" | "%" | "<<" | ">>",
  a: Expr,
  b: Expr,
): Expr => ({ kind: "op", op: o, a, b });
export const cond = (test: Expr, t: Expr, f: Expr): Expr => ({
  kind: "cond",
  test,
  t,
  f,
});
export const peek = (bits: number, offset?: Expr): Expr =>
  offset === undefined ? { kind: "peek", bits } : { kind: "peek", bits, offset };

export function peekEnvKey(offset: number, bits: number): string {
  return `__peek__${offset}__${bits}`;
}

export class MissingRefError extends Error {
  constructor(public readonly field: string) {
    super(`evalExpr: missing reference "${field}"`);
    this.name = "MissingRefError";
  }
}

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
        case "+": return a + b;
        case "-": return a - b;
        case "*": return a * b;
        case "/":
          if (b === 0) throw new Error("evalExpr: division by zero");
          return Math.trunc(a / b);
        case "%":
          if (b === 0) throw new Error("evalExpr: modulo by zero");
          return a % b;
        case "<<": return (a << b) | 0;
        case ">>": return a >> b;
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
      const offsetVal = expr.offset !== undefined ? evalExpr(expr.offset, env) : 0;
      const key = `__peek__${offsetVal}__${expr.bits}`;
      return env.get(key) ?? 0;
    }
    default: {
      const _exhaustive: never = expr;
      throw new Error(
        `evalExpr: unknown expression kind "${(_exhaustive as { kind: string }).kind}"`,
      );
    }
  }
}

export function exprRefs(expr: Expr): string[] {
  const out: string[] = [];
  walkExpr(expr, out);
  return out;
}

function walkExpr(expr: Expr, out: string[]): void {
  switch (expr.kind) {
    case "lit": return;
    case "ref": out.push(expr.field); return;
    case "op": walkExpr(expr.a, out); walkExpr(expr.b, out); return;
    case "cond":
      walkExpr(expr.test, out);
      walkExpr(expr.t, out);
      walkExpr(expr.f, out);
      return;
    case "peek":
      if (expr.offset !== undefined) walkExpr(expr.offset, out);
      return;
    default: {
      const _exhaustive: never = expr;
      throw new Error(
        `exprRefs: unhandled Expr kind ${String((_exhaustive as { kind?: string }).kind)}`,
      );
    }
  }
}
