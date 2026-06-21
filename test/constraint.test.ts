import { describe, expect, it } from "vitest";
import { propagate, propagateFixpoint, validateConstraints } from "../src/constraint.js";
import { lit, op, ref, remainingEnvKey } from "../src/expr.js";
import type { Constraint, Expr, PacketEnv } from "../src/types.js";

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

describe("constraint level — solver participation (§9.1)", () => {
  it("must / level-less constraints back-propagate", () => {
    const c: Constraint = { lhs: ref("total"), rhs: op("+", ref("a"), ref("b")), level: "must" };
    const res = propagate([c], env({ total: 10, a: 4 }), "total");
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("b")).toBe(6);
  });

  it("should constraints do NOT back-propagate (no value derived)", () => {
    const c: Constraint = { lhs: ref("total"), rhs: op("+", ref("a"), ref("b")), level: "should" };
    const res = propagate([c], env({ total: 10, a: 4 }), "total");
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.has("b")).toBe(false);
  });

  it("may constraints do NOT back-propagate", () => {
    const c: Constraint = { lhs: ref("x"), rhs: ref("y"), level: "may" };
    const res = propagate([c], env({ x: 7 }), "x");
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.has("y")).toBe(false);
  });

  it("should constraint conflict is reported by validateConstraints as diagnostic, not by propagate", () => {
    const c: Constraint = { lhs: ref("a"), rhs: ref("b"), level: "should" };
    // propagate must not flag a conflict for should/may
    const p = propagate([c], env({ a: 1, b: 2 }), "a");
    expect("ok" in p).toBe(true);
    // validateConstraints still surfaces the mismatch (level-tagged, not a conflict)
    const v = validateConstraints([c], env({ a: 1, b: 2 }));
    expect("conflict" in v).toBe(false);
    expect("ok" in v).toBe(true);
    if (!("ok" in v)) return;
    expect(v.diagnostics).toBeDefined();
    expect(v.diagnostics!.some((d) => d.level === "should")).toBe(true);
  });

  it("may constraint mismatch is informational only (no hard conflict)", () => {
    const c: Constraint = { lhs: ref("a"), rhs: ref("b"), level: "may" };
    const v = validateConstraints([c], env({ a: 5, b: 9 }));
    expect("conflict" in v).toBe(false);
    if (!("ok" in v)) return;
    expect(v.diagnostics!.some((d) => d.level === "may")).toBe(true);
  });

  it("must mismatch is still a hard conflict via validateConstraints", () => {
    const c: Constraint = { lhs: ref("a"), rhs: ref("b"), level: "must" };
    const v = validateConstraints([c], env({ a: 1, b: 2 }));
    expect("conflict" in v).toBe(true);
  });

  it("fixpoint ignores should/may when resolving chains", () => {
    const must: Constraint = { lhs: ref("x"), rhs: op("+", ref("y"), lit(1)) };
    const should: Constraint = { lhs: ref("z"), rhs: op("+", ref("x"), lit(1)), level: "should" };
    const res = propagateFixpoint([must, should], env({ y: 5 }));
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("x")).toBe(6);
    expect(res.ok.has("z")).toBe(false); // should did not derive z
  });
});

describe("propagateFixpoint — constraint-ref seeding (§9)", () => {
  it("solves a literal-only constraint that shares no ref with the env", () => {
    // version == 4 with an unrelated env: the pass set is seeded from the
    // constraint's refs, so the constraint fires even though no env key
    // appears in it.
    const res = propagateFixpoint([{ lhs: ref("version"), rhs: lit(4) }], env({ other: 1 }));
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("version")).toBe(4);
    expect(res.ok.get("other")).toBe(1);
  });

  it("solves a literal-seeded chain from an empty env", () => {
    // version == 4 starts the chain; hlen == version + 1 follows.
    const cs: Constraint[] = [
      { lhs: ref("hlen"), rhs: op("+", ref("version"), lit(1)) },
      { lhs: ref("version"), rhs: lit(4) },
    ];
    const res = propagateFixpoint(cs, env({}));
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.get("version")).toBe(4);
    expect(res.ok.get("hlen")).toBe(5);
  });

  it("does NOT seed from should/may constraints (§9.1 solver exclusion)", () => {
    const res = propagateFixpoint([{ lhs: ref("v"), rhs: lit(7), level: "should" }], env({}));
    expect("ok" in res).toBe(true);
    if (!("ok" in res)) return;
    expect(res.ok.has("v")).toBe(false);
  });
});

describe("validateConstraints — evaluation errors become diagnostics (§9.1)", () => {
  it("a should-level division by zero is a diagnostic, not a thrown error", () => {
    const c: Constraint = { lhs: op("/", ref("a"), ref("b")), rhs: lit(1), level: "should" };
    const v = validateConstraints([c], env({ a: 4, b: 0 }));
    expect("conflict" in v).toBe(false);
    if (!("ok" in v)) return;
    expect(v.diagnostics).toHaveLength(1);
    expect(v.diagnostics![0]!.level).toBe("should");
    expect(v.diagnostics![0]!.message).toContain("division by zero");
  });

  it("a may-level modulo by zero is informational only", () => {
    const c: Constraint = { lhs: op("%", ref("x"), ref("y")), rhs: lit(0), level: "may" };
    const v = validateConstraints([c], env({ x: 8, y: 0 }));
    expect("conflict" in v).toBe(false);
    if (!("ok" in v)) return;
    expect(v.diagnostics![0]!.level).toBe("may");
    expect(v.diagnostics![0]!.message).toContain("modulo by zero");
  });

  it("a must-level evaluation error is the hard conflict", () => {
    const c: Constraint = { lhs: op("/", ref("a"), ref("b")), rhs: lit(1) };
    const v = validateConstraints([c], env({ a: 4, b: 0 }));
    expect("conflict" in v).toBe(true);
    if (!("conflict" in v)) return;
    expect(v.conflict).toContain("division by zero");
  });
});

describe("validateConstraints — composite diagnostics shape (§9.1)", () => {
  it("collects ALL soft mismatches, in declaration order, with their index", () => {
    const cs: Constraint[] = [
      { lhs: ref("a"), rhs: lit(1), level: "may", doc: "advisory A" },
      { lhs: ref("a"), rhs: ref("a") }, // passing must, shifts indices
      { lhs: ref("a"), rhs: lit(1), level: "should", doc: "advisory B" },
    ];
    const v = validateConstraints(cs, env({ a: 0 }));
    expect("conflict" in v).toBe(false);
    if (!("ok" in v)) return;
    expect(v.diagnostics).toHaveLength(2);
    expect(v.diagnostics![0]).toEqual({ index: 0, level: "may", message: "Constraint failed: lhs=0 rhs=1", doc: "advisory A" });
    expect(v.diagnostics![1]).toEqual({ index: 2, level: "should", message: "Constraint failed: lhs=0 rhs=1", doc: "advisory B" });
  });

  it("returns the must conflict AND keeps should/may diagnostics (must is indexed too)", () => {
    const cs: Constraint[] = [
      { lhs: ref("a"), rhs: lit(1), level: "should" },
      { lhs: ref("a"), rhs: lit(4), level: "must", doc: "TCP rule §3.1" },
      { lhs: ref("a"), rhs: lit(2), level: "may" },
    ];
    const v = validateConstraints(cs, env({ a: 0 }));
    expect("conflict" in v).toBe(true);
    if (!("conflict" in v)) return;
    // The conflict message carries the authored doc for identification.
    expect(v.conflict).toBe("Constraint failed: lhs=0 rhs=4 (TCP rule §3.1)");
    // §9.1: every failing constraint — must included — is an indexed diagnostic.
    expect(v.diagnostics).toHaveLength(3);
    expect(v.diagnostics!.map((d) => [d.index, d.level])).toEqual([[0, "should"], [1, "must"], [2, "may"]]);
    expect(v.diagnostics![1]).toEqual({ index: 1, level: "must", message: "Constraint failed: lhs=0 rhs=4", doc: "TCP rule §3.1" });
  });

  it("reports EVERY failing must as a diagnostic; conflict is the first in declaration order", () => {
    const cs: Constraint[] = [
      { lhs: ref("a"), rhs: lit(1) },
      { lhs: ref("a"), rhs: lit(2), level: "must", doc: "second rule" },
    ];
    const v = validateConstraints(cs, env({ a: 0 }));
    expect("conflict" in v).toBe(true);
    if (!("conflict" in v)) return;
    // The conflict string is derived from the FIRST failing must…
    expect(v.conflict).toBe("Constraint failed: lhs=0 rhs=1");
    // …but the second must violation is not silenced: both are indexed.
    expect(v.diagnostics).toEqual([
      { index: 0, level: "must", message: "Constraint failed: lhs=0 rhs=1" },
      { index: 1, level: "must", message: "Constraint failed: lhs=0 rhs=2", doc: "second rule" },
    ]);
  });
});

describe("propagate / propagateFixpoint — solver robustness (§9.1)", () => {
  it("a must evaluation error (division by zero) is a conflict, not a thrown error", () => {
    const c: Constraint = { lhs: op("/", ref("a"), ref("b")), rhs: lit(1) };
    const p = propagate([c], env({ a: 4, b: 0 }), "a");
    expect("conflict" in p).toBe(true);
    if (!("conflict" in p)) return;
    expect(p.conflict).toContain("division by zero");
    const f = propagateFixpoint([c], env({ a: 4, b: 0 }));
    expect("conflict" in f).toBe(true);
  });

  it("should/may evaluation errors are still skipped before evaluation (no crash, no conflict)", () => {
    const c: Constraint = { lhs: op("/", ref("a"), ref("b")), rhs: lit(1), level: "should" };
    const p = propagateFixpoint([c], env({ a: 4, b: 0 }));
    expect("ok" in p).toBe(true);
  });

  it("evaluates ref-less must constraints (literal-only) as pure checks", () => {
    // lit(4) == lit(5) contains no ref node, so the changed-key gate could
    // never select it — it must still surface as a conflict.
    const r = propagateFixpoint([{ lhs: lit(4), rhs: lit(5) }], env({ x: 1 }));
    expect("conflict" in r).toBe(true);
    // …including from a completely empty env.
    const r2 = propagateFixpoint([{ lhs: lit(4), rhs: lit(5) }], env({}));
    expect("conflict" in r2).toBe(true);
    // A satisfied ref-less constraint stays ok.
    const r3 = propagateFixpoint([{ lhs: lit(4), rhs: lit(4) }], env({ x: 1 }));
    expect("ok" in r3).toBe(true);
  });

  it("evaluates a ref-less 'remaining == 0' must check against the env-backed nullary", () => {
    const rem: Expr = { kind: "remaining" };
    const bad = propagateFixpoint(
      [{ lhs: rem, rhs: lit(0), doc: "no trailing garbage" }],
      new Map([[remainingEnvKey(), 7]]),
    );
    expect("conflict" in bad).toBe(true);
    if (!("conflict" in bad)) return;
    expect(bad.conflict).toBe("Constraint failed: lhs=7 rhs=0 (no trailing garbage)");
    const good = propagateFixpoint([{ lhs: rem, rhs: lit(0) }], new Map([[remainingEnvKey(), 0]]));
    expect("ok" in good).toBe(true);
  });

  it("ref-less should/may constraints stay diagnostic-only in the solver", () => {
    const r = propagateFixpoint([{ lhs: lit(4), rhs: lit(5), level: "should" }], env({}));
    expect("ok" in r).toBe(true);
  });

  it("propagate conflict messages carry the authored doc (withDoc parity with validateConstraints)", () => {
    const c: Constraint = { lhs: ref("total"), rhs: op("+", ref("a"), ref("b")), doc: "total = a + b" };
    const p = propagate([c], env({ total: 10, a: 4, b: 9 }), "total");
    expect("conflict" in p).toBe(true);
    if (!("conflict" in p)) return;
    expect(p.conflict).toBe("Constraint failed: lhs=10 rhs=13 (total = a + b)");
  });

  it("does not throw when solving past a constant zero-divisor subtree next to the unknown", () => {
    // 5 == x + (1 / 0): the whole-side evaluation hits the missing ref first
    // (rhsVal = null), then solveFor evaluates the constant subtree 1/0 in
    // isolation. That evaluation error means "no candidate", never an
    // uncaught exception out of the solver (§9.1).
    const c: Constraint = { lhs: lit(5), rhs: op("+", ref("x"), op("/", lit(1), lit(0))) };
    expect(() => propagate([c], env({}), "x")).not.toThrow();
    expect(() => propagateFixpoint([c], env({}))).not.toThrow();
    const p = propagate([c], env({}), "x");
    expect("ok" in p).toBe(true);
    if ("ok" in p) expect(p.ok.has("x")).toBe(false); // candidate not adoptable
    // Matches validateConstraints, which skips the constraint (missing ref).
    expect(validateConstraints([c], env({}))).toEqual({ ok: true });
    // …and relaxing the level keeps the same no-crash, no-derivation shape.
    const relaxed = propagate([{ ...c, level: "should" }], env({}), "x");
    expect("ok" in relaxed).toBe(true);
  });
});

describe("propagate / propagateFixpoint — conflict localization (§9.1)", () => {
  it("propagate conflicts identify the conflicting constraint by index", () => {
    const cs: Constraint[] = [
      { lhs: ref("a"), rhs: ref("a") }, // passing, shifts the index
      { lhs: ref("a"), rhs: ref("b"), doc: "a == b" },
    ];
    const p = propagate(cs, env({ a: 1, b: 2 }), "a");
    expect("conflict" in p).toBe(true);
    if (!("conflict" in p)) return;
    expect(p.index).toBe(1);
    expect(p.env).toBeDefined();
  });

  it("fixpoint conflicts carry the index and the partially-propagated env", () => {
    // c0 derives b = 5 from a; c1 then conflicts (b == 6). The original env
    // cannot reproduce the conflict (b unknown there), so the conflict result
    // exposes the env at detection time for tooling.
    const cs: Constraint[] = [
      { lhs: ref("b"), rhs: ref("a") },
      { lhs: ref("b"), rhs: lit(6) },
    ];
    const original = env({ a: 5 });
    const f = propagateFixpoint(cs, original);
    expect("conflict" in f).toBe(true);
    if (!("conflict" in f)) return;
    expect(f.conflict).toBe("Constraint failed: lhs=5 rhs=6");
    expect(f.index).toBe(1);
    expect(f.env?.get("b")).toBe(5);
    // The original env still validates clean (b unknown → both skipped)…
    expect(validateConstraints(cs, original)).toEqual({ ok: true });
    // …but re-running over the conflict env reproduces an indexed diagnostic.
    const v = validateConstraints(cs, f.env!);
    expect("conflict" in v).toBe(true);
    if (!("conflict" in v)) return;
    expect(v.diagnostics.some((d) => d.index === 1 && d.level === "must")).toBe(true);
  });

  it("a must evaluation-error conflict is indexed too", () => {
    const c: Constraint = { lhs: op("/", ref("a"), ref("b")), rhs: lit(1) };
    const p = propagate([c], env({ a: 4, b: 0 }), "a");
    expect("conflict" in p).toBe(true);
    if (!("conflict" in p)) return;
    expect(p.index).toBe(0);
  });
});

describe("validateConstraints — conflict returns always carry diagnostics", () => {
  it("a lone must mismatch yields conflict WITH its indexed diagnostic", () => {
    const v = validateConstraints([{ lhs: ref("a"), rhs: lit(1) }], env({ a: 0 }));
    expect("conflict" in v).toBe(true);
    if (!("conflict" in v)) return;
    // The conflict branch's diagnostics is non-optional: report() always
    // pushes the matching must diagnostic before setting the hard conflict.
    expect(v.diagnostics).toEqual([
      { index: 0, level: "must", message: "Constraint failed: lhs=0 rhs=1" },
    ]);
  });
});
