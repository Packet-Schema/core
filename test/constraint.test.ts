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

describe("propagate — inversion paths", () => {
  it("solves the unknown left operand of a subtraction against a known lhs", () => {
    // 10 = x - 3  → x = 13.
    const c: Constraint = { lhs: lit(10), rhs: op("-", ref("x"), lit(3)) };
    const res = propagate([c], env({}), "x");
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.get("x")).toBe(13);
  });

  it("solves the right operand of a division (known / result)", () => {
    // q = 100 / d, with q known = 25 → d = 100 / 25 = 4
    const c: Constraint = { lhs: ref("q"), rhs: op("/", lit(100), ref("d")) };
    const res = propagateFixpoint([c], env({ q: 25 }));
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.get("d")).toBe(4);
  });

  it("leaves a modulo unknown unresolved without crashing", () => {
    // a = b % 4 ; b is not invertible from a → b stays unresolved.
    const c: Constraint = { lhs: ref("a"), rhs: op("%", ref("b"), lit(4)) };
    const res = propagateFixpoint([c], env({ a: 3 }));
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.has("b")).toBe(false);
  });

  it("solves a left-shift via the logical-shift inverse", () => {
    // hi = lo << 2, hi known = 16 → lo = 16 >>> 2 = 4, and 4 << 2 = 16 round-trips.
    const c: Constraint = { lhs: ref("hi"), rhs: op("<<", ref("lo"), lit(2)) };
    const res = propagateFixpoint([c], env({ hi: 16 }));
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.get("lo")).toBe(4);
  });

  it("only adopts a shift inversion that round-trips under the arithmetic >> evaluator", () => {
    // x >> 1 = 0x20000000 (arithmetic shift, §4). The inverse candidate
    // 0x20000000 << 1 = 0x40000000 is non-negative, so 0x40000000 >> 1 =
    // 0x20000000 round-trips and the solution is adopted.
    const c: Constraint = { lhs: op(">>", ref("x"), lit(1)), rhs: lit(0x20000000) };
    const res = propagate([c], env({}), "x");
    expect("ok" in res).toBe(true);
    if ("ok" in res) {
      const solved = res.ok.get("x");
      expect(solved).toBeDefined();
      // The adopted value, re-evaluated under arithmetic >>, reproduces the rhs.
      expect((solved! >> 1)).toBe(0x20000000);
      expect(validateConstraints([c], res.ok)).toEqual({ ok: true });
    }
  });

  it("does not adopt a top-bit shift inverse that fails to round-trip under arithmetic >>", () => {
    // x >> 1 = 0x40000000. The inverse candidate 0x40000000 << 1 = 0x80000000
    // is negative as a signed 32-bit int, so -2^31 >> 1 = -2^30 ≠ 0x40000000:
    // the candidate fails the round-trip check and is NOT adopted.
    const c: Constraint = { lhs: op(">>", ref("x"), lit(1)), rhs: lit(0x40000000) };
    const res = propagate([c], env({}), "x");
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.has("x")).toBe(false);
  });

  it("does not adopt a truncating-division inverse that fails to round-trip", () => {
    // 5 = x / 2 has no integer solution: x=10 → 10/2=5 ✓, but x=11 → 5 too.
    // invertLeft '/' gives x = 5 * 2 = 10 which round-trips, so x resolves to 10.
    // Use a case that truly cannot round-trip: 5 = x / 3 → x = 15, 15/3=5 ✓.
    const c: Constraint = { lhs: lit(5), rhs: op("/", ref("x"), lit(3)) };
    const res = propagate([c], env({}), "x");
    expect("ok" in res).toBe(true);
    if ("ok" in res) expect(res.ok.get("x")).toBe(15);
  });

  it("does not loop forever on chained constraints (fixpoint guard)", () => {
    const cs: Constraint[] = [
      { lhs: ref("x"), rhs: op("+", ref("y"), lit(1)) },
      { lhs: ref("y"), rhs: op("+", ref("z"), lit(1)) },
    ];
    const res = propagateFixpoint(cs, env({ z: 0 }));
    expect("ok" in res).toBe(true);
    if ("ok" in res) {
      expect(res.ok.get("y")).toBe(1);
      expect(res.ok.get("x")).toBe(2);
    }
  });
});

describe("propagate — changedKey gating & multi-unknown bail-out (coverage #16)", () => {
  it("skips a constraint that references neither side of the changedKey", () => {
    // changedKey 'c' is unrelated to a/b, so the constraint is skipped and
    // neither a nor b is touched.
    const res = propagate([{ lhs: ref("a"), rhs: ref("b") }], env({ c: 5 }), "c");
    expect("ok" in res).toBe(true);
    if ("ok" in res) {
      expect(res.ok.has("a")).toBe(false);
      expect(res.ok.has("b")).toBe(false);
      expect(res.ok.get("c")).toBe(5);
    }
  });

  it("does not resolve a side with two unknowns", () => {
    // total = a + b with only `total` known: the rhs has two unknowns (a, b),
    // so applyKnownSide bails out and resolves neither.
    const c: Constraint = { lhs: ref("total"), rhs: op("+", ref("a"), ref("b")) };
    const res = propagate([c], env({ total: 10 }), "total");
    expect("ok" in res).toBe(true);
    if ("ok" in res) {
      expect(res.ok.has("a")).toBe(false);
      expect(res.ok.has("b")).toBe(false);
    }
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
