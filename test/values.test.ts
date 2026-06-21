import { describe, expect, it } from "vitest";
import { resolveValueEntry, matchesPattern } from "../src/values.js";
import type { ValueEntry } from "../src/types.js";

const DSCP: ValueEntry[] = [
  { value: 0, name: "CS0", level: "must" },
  { value: 46, name: "EF", level: "must" },
  { range: [1, 63], name: "OTHER", level: "may" },
];

describe("resolveValueEntry (§5.3)", () => {
  it("returns the exact value match", () => {
    expect(resolveValueEntry(DSCP, 46)?.name).toBe("EF");
  });

  it("exact value wins over a covering range even when the range is listed first", () => {
    // Range entry precedes the exact entry in array order; exact must still win.
    const v: ValueEntry[] = [
      { range: [0, 63], name: "ANY" },
      { value: 46, name: "EF" },
    ];
    expect(resolveValueEntry(v, 46)?.name).toBe("EF");
    expect(resolveValueEntry(v, 10)?.name).toBe("ANY");
  });

  it("falls back to the first containing range", () => {
    expect(resolveValueEntry(DSCP, 10)?.name).toBe("OTHER");
  });

  it("returns undefined for out-of-list values (open dictionary)", () => {
    expect(resolveValueEntry(DSCP, 99)).toBeUndefined();
  });

  it("returns undefined when there is no dictionary", () => {
    expect(resolveValueEntry(undefined, 0)).toBeUndefined();
  });

  it("handles negative values on signed fields", () => {
    const signed: ValueEntry[] = [{ value: -1, name: "SENTINEL" }, { range: [-8, -2], name: "NEG" }];
    expect(resolveValueEntry(signed, -1)?.name).toBe("SENTINEL");
    expect(resolveValueEntry(signed, -5)?.name).toBe("NEG");
    expect(resolveValueEntry(signed, 0)).toBeUndefined();
  });

  it("classifies a non-contiguous pool via pattern (DSCP experimental xxxx11)", () => {
    // DSCP 6-bit: named points plus the "xxxx11" experimental/local-use pool.
    const dscp: ValueEntry[] = [
      { value: 46, name: "EF", level: "must" },
      { pattern: "xxxx11", name: "EXP", level: "may" },
    ];
    expect(resolveValueEntry(dscp, 46)?.name).toBe("EF");      // exact wins
    expect(resolveValueEntry(dscp, 0b000111)?.name).toBe("EXP"); // 7 ends in 11
    expect(resolveValueEntry(dscp, 0b101011)?.name).toBe("EXP"); // 43 ends in 11
    expect(resolveValueEntry(dscp, 0b001000)).toBeUndefined();   // 8 — not exp, no name
  });

  it("treats trailing pattern length as don't-care ('11' ≡ 'xxxx11')", () => {
    const v: ValueEntry[] = [{ pattern: "11", name: "EXP" }];
    expect(resolveValueEntry(v, 0b101011)?.name).toBe("EXP");
    expect(resolveValueEntry(v, 0b101000)).toBeUndefined();
  });

  it("matches fully-specified patterns and ignores x bits", () => {
    expect(matchesPattern("101110", 46)).toBe(true);
    expect(matchesPattern("101110", 47)).toBe(false);
    expect(matchesPattern("1xxxxx", 0b100000)).toBe(true);
    expect(matchesPattern("0xxxxx", 0b100000)).toBe(false);
  });

  it("is correct beyond 32 bits (no int32 wrap)", () => {
    // Only bit 40 is set. A naive `(v >> 40) & 1` coerces v to int32 (low 32
    // bits of 2^40 are 0) and would wrongly read bit 40 as 0.
    const v = 2 ** 40;
    // Pattern of length L: leftmost char is bit L-1.
    expect(matchesPattern("1" + "x".repeat(40), v)).toBe(true);   // bit40 == 1 ✓
    expect(matchesPattern("0" + "x".repeat(40), v)).toBe(false);  // bit40 == 0? no
    expect(matchesPattern("0" + "x".repeat(41), v)).toBe(true);   // bit41 == 0 ✓
    expect(matchesPattern("xxxx0", v)).toBe(true);                // bit0 == 0 ✓
    expect(matchesPattern("xxxx1", v)).toBe(false);               // bit0 == 1? no
  });

  it("tests negative (signed) values in two's complement", () => {
    expect(matchesPattern("1111", -1)).toBe(true);   // -1 = …1111
    expect(matchesPattern("1011", -5)).toBe(true);   // -5 = …11011, low4 = 1011
    expect(matchesPattern("1111", -5)).toBe(false);
  });

  it("is correct at the 2^52 boundary (within safe-integer range)", () => {
    const v = 2 ** 52; // bit 52 set, representable exactly
    expect(matchesPattern("1" + "x".repeat(52), v)).toBe(true);
    expect(matchesPattern("xxxx0", v)).toBe(true);
  });

  it("returns the matched entry verbatim: level stays undefined when omitted (consumer applies the §5.3 'absent ≡ may' default)", () => {
    // The core does NOT materialise the "absent ≡ may" default: the resolved
    // entry is the SAME object reference as the input array element, so shared
    // references and identity-based consumers keep working.
    const entries: ValueEntry[] = [
      { value: 46, name: "EF" },
      { range: [0, 7], name: "LOW" },
      { pattern: "xxxx11", name: "EXP" },
    ];
    const exact = resolveValueEntry(entries, 46);
    expect(exact).toBe(entries[0]); // identity, not a normalised copy
    expect(exact!.level).toBeUndefined();
    const ranged = resolveValueEntry(entries, 5);
    expect(ranged).toBe(entries[1]);
    expect(ranged!.level).toBeUndefined();
    const patterned = resolveValueEntry(entries, 0b1011);
    expect(patterned).toBe(entries[2]);
    expect(patterned!.level).toBeUndefined();
  });

  it("first array entry wins across forms: pattern before range (§5.3)", () => {
    // 7 = 0b111 matches BOTH the pattern and the range; array order decides.
    const v: ValueEntry[] = [
      { pattern: "xxxx11", name: "EXP" },
      { range: [0, 63], name: "ANY" },
    ];
    expect(resolveValueEntry(v, 7)?.name).toBe("EXP");
  });

  it("first array entry wins across forms: range before pattern (§5.3)", () => {
    const v: ValueEntry[] = [
      { range: [0, 63], name: "ANY" },
      { pattern: "xxxx11", name: "EXP" },
    ];
    expect(resolveValueEntry(v, 7)?.name).toBe("ANY");
    // A value outside the range still falls through to the pattern…
    expect(resolveValueEntry(v, 0b1000011)?.name).toBe("EXP");
    // …and exact `value` still beats both fallback forms regardless of order.
    expect(resolveValueEntry([...v, { value: 7, name: "SEVEN" }], 7)?.name).toBe("SEVEN");
  });

  it("overlapping ranges resolve first-wins in array order (open dictionary, §5.3)", () => {
    const v: ValueEntry[] = [
      { range: [0, 15], name: "LOW" },
      { range: [8, 63], name: "HIGH" },
    ];
    expect(resolveValueEntry(v, 10)?.name).toBe("LOW");  // both contain 10 → first wins
    expect(resolveValueEntry(v, 20)?.name).toBe("HIGH");
  });

  it("duplicate exact value entries resolve first-wins in array order (open dictionary, §5.3)", () => {
    // Duplicates are valid input (the dictionary is open and never rejects
    // overlap), so the resolution rule must be pinned: the FIRST exact match
    // in array order wins, by identity.
    const entries: ValueEntry[] = [
      { value: 5, name: "FIRST", level: "must", meta: { rfc: 791 } },
      { value: 5, name: "SECOND", level: "may", meta: { rfc: 9999 } },
    ];
    const r = resolveValueEntry(entries, 5);
    expect(r).toBe(entries[0]); // identity, not just a name match
    expect(r?.name).toBe("FIRST");
  });

  it("accepts uppercase X as a don't-care, equivalent to lowercase x (§5.3)", () => {
    expect(matchesPattern("X1", 3)).toBe(true);
    expect(matchesPattern("X1", 2)).toBe(false);
    // 0b0111 ends in 11; the XX bits are don't-care.
    expect(resolveValueEntry([{ pattern: "XX11", name: "EXP" }], 0b0111)?.name).toBe("EXP");
    // Mixed case behaves identically to the all-lowercase pattern (bit 1 must be 1).
    expect(matchesPattern("Xx1X", 0b0110)).toBe(true);
    expect(matchesPattern("xx1x", 0b0110)).toBe(true);
    expect(matchesPattern("Xx1X", 0b0100)).toBe(false);
    expect(matchesPattern("xx1x", 0b0100)).toBe(false);
  });

  it("never throws on non-finite/non-integer observed (returns no match)", () => {
    expect(matchesPattern("xxxx11", NaN)).toBe(false);
    expect(matchesPattern("xxxx11", Infinity)).toBe(false);
    expect(matchesPattern("xxxx11", -Infinity)).toBe(false);
    expect(matchesPattern("1", 1.5)).toBe(false);
    const v: ValueEntry[] = [{ value: 1, name: "A" }, { pattern: "xxxx11", name: "EXP" }, { range: [0, 9], name: "R" }];
    // All three matcher forms agree: a non-integer resolves to undefined, no crash.
    expect(resolveValueEntry(v, NaN)).toBeUndefined();
    expect(resolveValueEntry(v, Infinity)).toBeUndefined();
    expect(resolveValueEntry(v, 1.5)).toBeUndefined();
  });
});
