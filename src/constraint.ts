import { evalExpr, exprContains, MissingRefError, walkExpr } from "./expr.js";
import type { Constraint, Expr, PacketEnv } from "./types.js";

export type PropagateOk = { ok: PacketEnv };
export type PropagateConflict = { conflict: string };
export type PropagateResult = PropagateOk | PropagateConflict;

function singleRef(expr: Expr): string | null {
  if (expr.kind === "ref") return expr.field;
  return null;
}

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

function invertLeft(o: string, result: number, known: number): number | null {
  switch (o) {
    case "+": return result - known;
    case "-": return result + known;
    case "*": return known === 0 ? null : Math.trunc(result / known);
    case "/": return result * known;
    case "%": return null;
    case "<<": return result >> known;
    case ">>": return (result << known) | 0;
  }
  return null;
}

function invertRight(o: string, result: number, known: number): number | null {
  switch (o) {
    case "+": return result - known;
    case "-": return known - result;
    case "*": return known === 0 ? null : Math.trunc(result / known);
    case "/": return result === 0 ? null : Math.trunc(known / result);
    case "%": return null;
    case "<<": return null;
    case ">>": return null;
  }
  return null;
}

export function propagate(
  constraints: Constraint[],
  env: PacketEnv,
  changedKey: string,
): PropagateResult {
  const next: PacketEnv = new Map(env);
  for (const c of constraints) {
    const lhsRef = singleRef(c.lhs);
    const rhsRef = singleRef(c.rhs);
    const lhsHas = containsRef(c.lhs, changedKey);
    const rhsHas = containsRef(c.rhs, changedKey);
    if (!lhsHas && !rhsHas) continue;
    if (lhsHas) {
      const lhsVal = evalConst(c.lhs, next);
      if (lhsVal === null) continue;
      if (rhsRef) {
        next.set(rhsRef, lhsVal);
      } else {
        const targets = uniqueRefs(c.rhs);
        if (targets.length === 1) {
          const solved = solveFor(c.rhs, targets[0]!, lhsVal, next);
          if (solved !== null) next.set(targets[0]!, solved);
        } else {
          const rhsVal = evalConst(c.rhs, next);
          if (rhsVal !== null && rhsVal !== lhsVal)
            return { conflict: `Constraint failed: lhs=${lhsVal} rhs=${rhsVal}` };
        }
      }
      continue;
    }
    if (rhsHas) {
      const rhsVal = evalConst(c.rhs, next);
      if (rhsVal === null) continue;
      if (lhsRef) {
        next.set(lhsRef, rhsVal);
      } else {
        const targets = uniqueRefs(c.lhs);
        if (targets.length === 1) {
          const solved = solveFor(c.lhs, targets[0]!, rhsVal, next);
          if (solved !== null) next.set(targets[0]!, solved);
        } else {
          const lhsVal = evalConst(c.lhs, next);
          if (lhsVal !== null && lhsVal !== rhsVal)
            return { conflict: `Constraint failed: lhs=${lhsVal} rhs=${rhsVal}` };
        }
      }
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
 * field is resolved in a pass. Seeds the pass set from every key in `env`.
 */
export function propagateFixpoint(
  constraints: Constraint[],
  env: PacketEnv,
): PropagateResult {
  let current: PacketEnv = new Map(env);
  let changed = true;
  let guard = 0;
  const MAX_PASSES = 1000;
  while (changed && guard++ < MAX_PASSES) {
    changed = false;
    for (const key of [...current.keys()]) {
      const res = propagate(constraints, current, key);
      if ("conflict" in res) return res;
      // Adopt newly resolved keys.
      for (const [k, v] of res.ok) {
        if (current.get(k) !== v) { current = res.ok; changed = true; break; }
      }
    }
  }
  return { ok: current };
}

export function validateConstraints(
  constraints: Constraint[],
  env: PacketEnv,
): { ok: true } | { conflict: string } {
  for (const c of constraints) {
    const l = evalConst(c.lhs, env);
    const r = evalConst(c.rhs, env);
    if (l === null || r === null) continue;
    if (l !== r) return { conflict: `Constraint failed: lhs=${l} rhs=${r}` };
  }
  return { ok: true };
}
