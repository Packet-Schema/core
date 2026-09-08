import { evalExpr, exprContains, MissingRefError, walkExpr } from "./expr.js";
import type { Constraint, Expr, NormativeLevel, PacketEnv } from "./types.js";

export type PropagateOk = { ok: PacketEnv };
/**
 * A hard solver conflict (§9.1). `index` identifies the conflicting constraint
 * within the `constraints` array (so an LSP can map the conflict back to a
 * source range) and `env` carries the partially-propagated environment at the
 * moment the conflict was detected — re-running `validateConstraints` over it
 * reproduces the conflict with full per-constraint diagnostics. Both fields
 * are additive (older callers that only read `conflict` keep working).
 */
export type PropagateConflict = {
  conflict: string;
  index?: number;
  env?: PacketEnv;
};
export type PropagateResult = PropagateOk | PropagateConflict;

function solveFor(
  expr: Expr,
  targetRef: string,
  known: number,
  env: PacketEnv,
): number | null {
  if (expr.kind === "ref") return expr.field === targetRef ? known : null;
  if (expr.kind !== "op") return null; // only linear op-trees are invertible
  const aHas = containsRef(expr.a, targetRef);
  const bHas = containsRef(expr.b, targetRef);
  if (aHas === bHas) return null;
  if (aHas) {
    const bVal = evalConst(expr.b, env);
    if (bVal === null) return null;
    const peeled = invertLeft(expr.op, known, bVal);
    if (peeled === null) return null;
    return solveFor(expr.a, targetRef, peeled, env);
  } else {
    const aVal = evalConst(expr.a, env);
    if (aVal === null) return null;
    const peeled = invertRight(expr.op, known, aVal);
    if (peeled === null) return null;
    return solveFor(expr.b, targetRef, peeled, env);
  }
}

function containsRef(expr: Expr, target: string): boolean {
  return exprContains(expr, (e) => e.kind === "ref" && e.field === target);
}

function evalConst(expr: Expr, env: PacketEnv): number | null {
  try {
    return evalExpr(expr, env);
  } catch (e) {
    if (e instanceof MissingRefError) return null;
    throw e;
  }
}

// Invert `a OP known = result` for `a` (the unknown on the LEFT operand).
// Shifts use the semantics of expr.ts (`<<` → `(a<<b)>>>0` unsigned, `>>` →
// arithmetic `a>>b`, §4). They are lossy and not uniquely invertible, so the
// candidate produced here is verified by re-evaluation in applyKnownSide
// before adoption.
function invertLeft(o: string, result: number, known: number): number | null {
  switch (o) {
    case "+":
      return result - known;
    case "-":
      return result + known;
    case "*":
      return known === 0 ? null : Math.trunc(result / known);
    case "/":
      return result * known;
    case "%":
      return null;
    case "<<":
      return result >>> known; // inverse of (a << known)>>>0
    case ">>":
      return (result << known) | 0; // inverse of arithmetic a >> known
  }
  return null;
}

// Invert `known OP b = result` for `b` (the unknown on the RIGHT operand).
function invertRight(o: string, result: number, known: number): number | null {
  switch (o) {
    case "+":
      return result - known;
    case "-":
      return known - result;
    case "*":
      return known === 0 ? null : Math.trunc(result / known);
    case "/":
      return result === 0 ? null : Math.trunc(known / result);
    case "%":
      return null;
    // Shift amount as the unknown is not soundly invertible.
    case "<<":
      return null;
    case ">>":
      return null;
  }
  return null;
}

/** Refs in `expr` whose value is not yet known in `env`. */
function unknownRefs(expr: Expr, env: PacketEnv): string[] {
  return uniqueRefs(expr).filter((r) => !env.has(r));
}

/**
 * Given that `known` is the value of one side of an equality, try to use it to
 * resolve the other (`other`) side: solve its single unknown, or detect a
 * conflict when it is fully determined and disagrees. `knownSide` names the
 * side `known` came from so conflict messages keep the lhs/rhs orientation,
 * and `c` supplies the authored doc string for the message (§9.1).
 */
function applyKnownSide(
  known: number,
  other: Expr,
  next: PacketEnv,
  knownSide: "lhs" | "rhs",
  c: Constraint,
): PropagateConflict | null {
  const unknowns = unknownRefs(other, next);
  if (unknowns.length === 0) {
    let otherVal: number | null;
    try {
      otherVal = evalConst(other, next);
    } catch (e) {
      // Mirror validateConstraints: a `must` expression that cannot be
      // evaluated is a hard conflict, never an uncaught exception.
      return {
        conflict: withDoc(
          `Constraint evaluation error: ${e instanceof Error ? e.message : String(e)}`,
          c,
        ),
      };
    }
    if (otherVal !== null && otherVal !== known) {
      const [l, r] =
        knownSide === "lhs" ? [known, otherVal] : [otherVal, known];
      return { conflict: withDoc(`Constraint failed: lhs=${l} rhs=${r}`, c) };
    }
    return null;
  }
  if (unknowns.length === 1) {
    // Like the probe below, an evaluation error while inverting (e.g. a
    // constant zero-divisor subtree next to the unknown ref) just means no
    // candidate can be derived — not a conflict, and never an uncaught
    // exception out of the solver. This matches validateConstraints, which
    // skips the constraint when a side cannot be evaluated.
    let solved: number | null;
    try {
      solved = solveFor(other, unknowns[0]!, known, next);
    } catch {
      solved = null;
    }
    if (solved !== null) {
      // Inversion through lossy operators (shifts, truncating division) is not
      // guaranteed to round-trip under the unsigned evaluator. Adopt the solved
      // value only if re-evaluating `other` actually reproduces `known`. An
      // evaluation error on the probe (e.g. the candidate lands as a zero
      // divisor) just means the candidate is not adoptable — not a conflict.
      const probe: PacketEnv = new Map(next);
      probe.set(unknowns[0]!, solved);
      let check: number | null;
      try {
        check = evalConst(other, probe);
      } catch {
        check = null;
      }
      if (check === known) next.set(unknowns[0]!, solved);
    }
  }
  return null;
}

export function propagate(
  constraints: Constraint[],
  env: PacketEnv,
  changedKey: string,
): PropagateResult {
  const next: PacketEnv = new Map(env);
  for (const [index, c] of constraints.entries()) {
    // Only `must` (and level-less) constraints back-propagate (§9.1). `should`/
    // `may` are diagnostic-only and excluded from both value derivation and the
    // conflict detection below, so relaxing a level never changes any
    // wire-parsed value (it can drop solver-derived values and hard-failure
    // detection that the `must` was providing — see §9.1).
    if (c.level !== undefined && c.level !== "must") continue;
    // A constraint with no ref node at all (literal-only, or built solely from
    // env-backed nullaries like `remaining`) can never match the changed-key
    // gate, yet may still be violated — always evaluate it as a pure check.
    const refLess =
      uniqueRefs(c.lhs).length === 0 && uniqueRefs(c.rhs).length === 0;
    if (
      !refLess &&
      !containsRef(c.lhs, changedKey) &&
      !containsRef(c.rhs, changedKey)
    )
      continue;
    let lhsVal: number | null;
    let rhsVal: number | null;
    try {
      lhsVal = evalConst(c.lhs, next);
      rhsVal = evalConst(c.rhs, next);
    } catch (e) {
      // Mirror validateConstraints: an evaluation error (e.g. division by zero
      // on wire-derived values) in a `must` constraint is a hard conflict, not
      // an uncaught exception out of the solver.
      return {
        conflict: withDoc(
          `Constraint evaluation error: ${e instanceof Error ? e.message : String(e)}`,
          c,
        ),
        index,
        env: next,
      };
    }
    if (lhsVal !== null && rhsVal !== null) {
      if (lhsVal !== rhsVal)
        return {
          conflict: withDoc(
            `Constraint failed: lhs=${lhsVal} rhs=${rhsVal}`,
            c,
          ),
          index,
          env: next,
        };
      continue;
    }
    if (lhsVal !== null) {
      const conflict = applyKnownSide(lhsVal, c.rhs, next, "lhs", c);
      if (conflict) return { ...conflict, index, env: next };
    } else if (rhsVal !== null) {
      const conflict = applyKnownSide(rhsVal, c.lhs, next, "rhs", c);
      if (conflict) return { ...conflict, index, env: next };
    }
  }
  return { ok: next };
}

function uniqueRefs(expr: Expr): string[] {
  const set = new Set<string>();
  walkExpr(expr, (e) => {
    if (e.kind === "ref") set.add(e.field);
  });
  return [...set];
}

/**
 * Fixpoint back-propagation (§9): re-run the constraint list until no new
 * field is resolved in a pass. Seeds the pass set from every key in `env`
 * UNION every ref mentioned by a `must` (or level-less) constraint, so a
 * constraint sharing no ref with the env — e.g. the literal-only
 * `version == 4` — still fires and can start a resolution chain (§9
 * "re-runs the full constraint list until no new fields are resolved").
 */
export function propagateFixpoint(
  constraints: Constraint[],
  env: PacketEnv,
): PropagateResult {
  let current: PacketEnv = new Map(env);
  const seedKeys = new Set<string>();
  for (const c of constraints) {
    if (c.level !== undefined && c.level !== "must") continue; // §9.1
    for (const r of uniqueRefs(c.lhs)) seedKeys.add(r);
    for (const r of uniqueRefs(c.rhs)) seedKeys.add(r);
  }
  let changed = true;
  let guard = 0;
  const MAX_PASSES = 1000;
  while (changed && guard++ < MAX_PASSES) {
    changed = false;
    const keys = new Set([...current.keys(), ...seedKeys]);
    // Even with no keys at all (empty env, ref-less constraints only), run one
    // pass so pure checks like `remaining == 0` still get evaluated.
    if (keys.size === 0) keys.add("");
    for (const key of keys) {
      const res = propagate(constraints, current, key);
      if ("conflict" in res) return res;
      // Adopt newly resolved keys.
      for (const [k, v] of res.ok) {
        if (current.get(k) !== v) {
          current = res.ok;
          changed = true;
          break;
        }
      }
    }
  }
  return { ok: current };
}

/**
 * A constraint mismatch diagnostic (§9.1). EVERY failing constraint — `must`
 * included — is reported as one of these: `should`/`may` mismatches are
 * advisories (warning/info), while a failing `must` additionally drives the
 * hard `conflict` (so a `must` violation appears both as the `conflict` string
 * and as a level-tagged entry here). `index` identifies the failing constraint
 * within the `constraints` array (so an LSP can map the diagnostic back to a
 * source range) and `doc` copies the constraint's authored doc string when
 * present.
 */
export type ConstraintDiagnostic = {
  index: number;
  level: NormativeLevel;
  message: string;
  doc?: string;
};

/** Append the constraint's authored doc to a message, when present. */
function withDoc(message: string, c: Constraint): string {
  return c.doc !== undefined ? `${message} (${c.doc})` : message;
}

/**
 * Evaluate every constraint for diagnostics (§9.1). `must` (and level-less)
 * mismatches become a hard `conflict`; `should`/`may` mismatches are collected
 * into `diagnostics` (level-tagged) so the caller can map them to warning/info
 * severities. `should`/`may` never produce a conflict, matching the solver's
 * back-propagation exclusion in `propagate`. EVERY failing constraint — `must`
 * included — also appears in `diagnostics` with its index, so an LSP can map
 * each violation (not just the first) back to a source range; the `conflict`
 * string is derived from the first failing `must` in declaration order.
 * Evaluation errors (e.g. division by zero in an expression) likewise never
 * escape as exceptions: they become a diagnostic at the constraint's level
 * (plus the hard conflict for `must`), so a single broken advisory constraint
 * cannot crash diagnostics generation.
 */
export function validateConstraints(
  constraints: Constraint[],
  env: PacketEnv,
):
  | { ok: true; diagnostics?: ConstraintDiagnostic[] }
  | { conflict: string; diagnostics: ConstraintDiagnostic[] } {
  const diagnostics: ConstraintDiagnostic[] = [];
  let hardConflict: string | null = null;
  for (const [index, c] of constraints.entries()) {
    const level = c.level ?? "must";
    const report = (message: string): void => {
      if (level === "must" && hardConflict === null)
        hardConflict = withDoc(message, c);
      diagnostics.push({
        index,
        level,
        message,
        ...(c.doc !== undefined ? { doc: c.doc } : {}),
      });
    };
    let l: number | null;
    let r: number | null;
    try {
      l = evalConst(c.lhs, env);
      r = evalConst(c.rhs, env);
    } catch (e) {
      report(
        `Constraint evaluation error: ${e instanceof Error ? e.message : String(e)}`,
      );
      continue;
    }
    if (l === null || r === null) continue;
    if (l !== r) report(`Constraint failed: lhs=${l} rhs=${r}`);
  }
  // A hard conflict is only ever set by report(), which always pushes the
  // matching `must` diagnostic first — so `diagnostics` is necessarily
  // non-empty here and the conflict return carries it unconditionally.
  if (hardConflict !== null) return { conflict: hardConflict, diagnostics };
  return diagnostics.length ? { ok: true, diagnostics } : { ok: true };
}
