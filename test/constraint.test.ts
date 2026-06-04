import { describe, expect, it } from "vitest";
import { propagate, propagateFixpoint, validateConstraints } from "../src/constraint.js";
import { lit, op, ref } from "../src/expr.js";
import type { Constraint, PacketEnv } from "../src/types.js";

const env = (e: Record<string, number>): PacketEnv => new Map(Object.entries(e));

describe("propagate — single constraint", () => {
  it("solves a single-unknown linear constraint", () => {
    // total = ihl * 4 + data  → solve data given total, ihl
    const c: Constraint = {
      lhs: ref("total"),
      rhs: op("+", op("*", ref("ihl"), lit(4)), ref("data")),
    };
    const res = propagate([c], env({ total: 28, ihl: 5 }), "total");
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("data")).toBe(8);
  });

  it("reports a conflict when both sides are known and unequal", () => {
    const c: Constraint = { lhs: ref("a"), rhs: ref("b") };
    const res = propagate([c], env({ a: 1, b: 2 }), "a");
    expect("conflict" in res).toBe(true);
  });
});

describe("propagateFixpoint — chained constraints", () => {
  it("resolves a chain across passes regardless of order", () => {
    // c1: x = y + 1 ; c2: z = x + 1   (c2 listed before c1)
    const c2: Constraint = { lhs: ref("z"), rhs: op("+", ref("x"), lit(1)) };
    const c1: Constraint = { lhs: ref("x"), rhs: op("+", ref("y"), lit(1)) };
    const res = propagateFixpoint([c2, c1], env({ y: 10 }));
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("x")).toBe(11);
    expect(res.ok.get("z")).toBe(12);
  });
});

describe("validateConstraints", () => {
  it("passes when both sides agree, skips unknowns", () => {
    expect(validateConstraints([{ lhs: ref("a"), rhs: ref("b") }], env({ a: 3, b: 3 }))).toEqual({ ok: true });
    expect(validateConstraints([{ lhs: ref("a"), rhs: ref("missing") }], env({ a: 3 }))).toEqual({ ok: true });
  });
  it("flags a mismatch", () => {
    const r = validateConstraints([{ lhs: ref("a"), rhs: ref("b") }], env({ a: 3, b: 4 }));
    expect("conflict" in r).toBe(true);
  });
});
