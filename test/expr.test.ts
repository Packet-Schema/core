import { describe, expect, it } from "vitest";
import {
  cond, evalExpr, evalExprOr, exprContains, exprRefs, lit, lookup, op, peek,
  peekEnvKey, ref, remaining, remainingEnvKey, wireSize, wireSizeEnvKey,
  MissingRefError,
} from "../src/expr.js";
import type { PacketEnv } from "../src/types.js";

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
