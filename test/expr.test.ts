import { describe, expect, it } from "vitest";
import {
  cond, evalExpr, evalExprOr, exprContains, exprRefs, lit, lookup, op, peek,
  peekEnvKey, ref, remaining, remainingEnvKey, wireSize, wireSizeEnvKey,
  prevIter, prevIterEnvKey, enclosingBits, enclosingBitsEnvKey,
  enclosingField, enclosingFieldEnvKey, MissingRefError,
} from "../src/expr.js";
import type { Expr, PacketEnv } from "../src/types.js";

const env = (entries: Record<string, number> = {}): PacketEnv =>
  new Map(Object.entries(entries));

describe("evalExpr — arithmetic", () => {
  it("evaluates literals and refs", () => {
    expect(evalExpr(lit(20), env())).toBe(20);
    expect(evalExpr(ref("x"), env({ x: 7 }))).toBe(7);
  });

  it("truncates division toward zero", () => {
    expect(evalExpr(op("/", lit(7), lit(2)), env())).toBe(3);
    expect(evalExpr(op("/", lit(-7), lit(2)), env())).toBe(-3);
  });

  it("throws on division/modulo by zero", () => {
    expect(() => evalExpr(op("/", lit(1), lit(0)), env())).toThrow(/division by zero/);
    expect(() => evalExpr(op("%", lit(1), lit(0)), env())).toThrow(/modulo by zero/);
  });

  // C6/§4: `%` is paired with truncated-toward-zero division, so the remainder
  // takes the sign of the dividend (JS remainder), NOT the Euclidean result.
  // Pin this so the spec wording and the implementation stay aligned.
  it("modulo takes the sign of the dividend (truncated, not Euclidean)", () => {
    expect(evalExpr(op("%", lit(-7), lit(3)), env())).toBe(-1); // not Euclidean 2
    expect(evalExpr(op("%", op("-", lit(1), lit(3)), lit(4)), env())).toBe(-2); // not 2
    expect(evalExpr(op("%", lit(7), lit(-3)), env())).toBe(1);
  });

  it("comparisons yield 0/1", () => {
    expect(evalExpr(op("==", lit(4), lit(4)), env())).toBe(1);
    expect(evalExpr(op("<", lit(4), lit(2)), env())).toBe(0);
    expect(evalExpr(op(">=", lit(4), lit(4)), env())).toBe(1);
  });

  it("bitwise ops operate as 32-bit", () => {
    expect(evalExpr(op("&", lit(0b1100), lit(0b1010)), env())).toBe(0b1000);
    expect(evalExpr(op("|", lit(0b1100), lit(0b1010)), env())).toBe(0b1110);
    expect(evalExpr(op("^", lit(0b1100), lit(0b1010)), env())).toBe(0b0110);
  });

  it("cond chooses branch on test != 0", () => {
    expect(evalExpr(cond(lit(1), lit(10), lit(20)), env())).toBe(10);
    expect(evalExpr(cond(lit(0), lit(10), lit(20)), env())).toBe(20);
  });
});

describe("evalExpr — missing refs", () => {
  it("throws MissingRefError for an unknown ref", () => {
    expect(() => evalExpr(ref("nope"), env())).toThrow(MissingRefError);
  });
  it("evalExprOr falls back for missing refs", () => {
    expect(evalExprOr(ref("nope"), env(), 0)).toBe(0);
    expect(evalExprOr(ref("nope"), env(), 5)).toBe(5);
  });
});

describe("evalExpr — context-dependent kinds", () => {
  it("lookup maps keys, truncates, misses to 0", () => {
    const table = { 9: 12, 10: 16, 15: 64 };
    expect(evalExpr(lookup(ref("dlc"), table), env({ dlc: 9 }))).toBe(12);
    expect(evalExpr(lookup(ref("dlc"), table), env({ dlc: 99 }))).toBe(0);
  });
  it("peek reads injected env key", () => {
    expect(evalExpr(peek(8), env({ [peekEnvKey(0, 8)]: 0x45 }))).toBe(0x45);
  });
  it("remaining / wireSize read reserved env keys", () => {
    expect(evalExpr(remaining(), env({ [remainingEnvKey()]: 12 }))).toBe(12);
    expect(evalExpr(wireSize("hdr"), env({ [wireSizeEnvKey("hdr")]: 20 }))).toBe(20);
  });

  it("evaluates shifts: unsigned 32-bit << and arithmetic >> (§4)", () => {
    expect(evalExpr(op("<<", lit(1), lit(4)), env())).toBe(16);
    expect(evalExpr(op(">>", lit(256), lit(2)), env())).toBe(64);
    // Left shift is masked to an unsigned 32-bit result: 1 << 31 is the
    // unsigned wire value 2147483648, not the signed -2147483648 (§4, fix #1).
    expect(evalExpr(op("<<", lit(1), lit(31)), env())).toBe(2147483648);
    expect(evalExpr(op("==", op("<<", lit(1), lit(31)), lit(2147483648)), env())).toBe(1);
    // Right shift is arithmetic (sign-propagating) per §4: 0x80000003 read as a
    // signed 32-bit integer is negative, so >> 1 sign-extends.
    expect(evalExpr(op(">>", lit(0x80000003), lit(1)), env())).toBe(-1073741823);
    // A non-negative operand shifts identically to the logical form.
    expect(evalExpr(op(">>", lit(0x40000000), lit(1)), env())).toBe(0x20000000);
  });

  it("prevIter / enclosingBits / enclosingField read reserved keys, default 0", () => {
    expect(evalExpr(prevIter("x"), env({ [prevIterEnvKey("x")]: 9 }))).toBe(9);
    expect(evalExpr(prevIter("x"), env())).toBe(0);
    expect(evalExpr(enclosingBits(), env({ [enclosingBitsEnvKey()]: 64 }))).toBe(64);
    expect(evalExpr(enclosingBits(), env())).toBe(0);
    expect(evalExpr(enclosingField("y"), env({ [enclosingFieldEnvKey("y")]: 7 }))).toBe(7);
    expect(evalExpr(enclosingField("y"), env())).toBe(0);
  });

  it("peek reads at a non-zero computed offset", () => {
    expect(evalExpr(peek(8, lit(2)), env({ [peekEnvKey(2, 8)]: 0xab }))).toBe(0xab);
  });

  it("throws on an unknown operator", () => {
    const bad = { kind: "op", op: "??", a: lit(1), b: lit(2) } as unknown as Expr;
    expect(() => evalExpr(bad, env())).toThrow(/unknown operator/);
  });
});

describe("exprRefs / exprContains", () => {
  it("collects plain refs only", () => {
    expect(exprRefs(op("+", ref("a"), op("*", ref("b"), lit(4))))).toEqual(["a", "b"]);
  });
  it("exprContains finds nested kinds", () => {
    expect(exprContains(op("+", ref("a"), remaining()), (e) => e.kind === "remaining")).toBe(true);
    expect(exprContains(op("+", ref("a"), lit(1)), (e) => e.kind === "peek")).toBe(false);
  });
});
