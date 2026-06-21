// Value-dictionary reverse lookup (§5.3).
//
// Tools (LSP hover, packet-understanding renderers, validators) observe a
// concrete field value and need its meaning, normative strength, and RFC
// provenance. `values` is an *open* dictionary: a value with no matching entry
// is still valid wire — the lookup simply returns `undefined` (out-of-list).

import type { ValueEntry } from "./types.js";

/**
 * Test a ternary bit-pattern (`0`/`1`/`x`) against an observed integer (§5.3).
 * The pattern reads like a binary literal: its rightmost character is bit 0.
 * Characters beyond the pattern's length are treated as don't-care, so `"11"`
 * and `"xxxx11"` are equivalent. `x`/`X` bits are ignored.
 *
 * Uses BigInt so patterns wider than 32 bits are correct — JS number bitwise
 * (`>>`, `&`) would coerce to 32 bits and wrap. Negative `observed` (signed
 * fields) is tested in two's complement via BigInt's arithmetic right shift.
 *
 * Precondition: `observed` is a safe integer (|value| ≤ 2^53). Non-integer,
 * NaN, or Infinity inputs return `false` (never throw). For wire values that
 * exceed 2^53 the caller must keep them as `bigint` and not round-trip through
 * `number`, which would already have lost precision before reaching here.
 */
export function matchesPattern(pattern: string, observed: number): boolean {
  if (!Number.isInteger(observed)) return false;
  const obs = BigInt(observed);
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[pattern.length - 1 - i];
    if (ch === "x" || ch === "X") continue;
    const bit = (obs >> BigInt(i)) & 1n;
    if (bit !== (ch === "1" ? 1n : 0n)) return false;
  }
  return true;
}

/**
 * Resolve an observed numeric value against a field's value dictionary.
 *
 * Resolution order (§5.3):
 *   1. an exact `value` match always wins,
 *   2. otherwise the first entry (array order) whose `range` contains it or
 *      whose `pattern` bit-predicate holds,
 *   3. otherwise `undefined` (out-of-list — still valid, just un-annotated).
 *
 * First-match semantics for overlapping range/pattern entries; PSDL does not
 * forbid overlap (the dictionary is annotational, not a closed enum).
 */
export function resolveValueEntry(
  values: readonly ValueEntry[] | undefined,
  observed: number,
): ValueEntry | undefined {
  // Observed wire values are integers; a non-integer (incl. NaN/Infinity) has no
  // meaning in the dictionary, so all three matcher forms agree on "no match".
  if (values === undefined || !Number.isInteger(observed)) return undefined;
  let fallback: ValueEntry | undefined;
  for (const ve of values) {
    if (ve.value !== undefined) {
      if (ve.value === observed) return ve;
    } else if (fallback === undefined) {
      if (ve.range !== undefined) {
        const [min, max] = ve.range;
        if (observed >= min && observed <= max) fallback = ve;
      } else if (ve.pattern !== undefined) {
        if (matchesPattern(ve.pattern, observed)) fallback = ve;
      }
    }
  }
  return fallback;
}
