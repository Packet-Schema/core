// §11.4 load-time lint warnings.
//
// These are ADVISORY, not hard errors: a document that trips every rule here is
// still a valid PSDL document and `validatePacket` returns no error for any of
// them. That distinction is why they live in their own channel rather than as
// `ValidationError`s — `ValidationError` carries no level, so a warning pushed
// there would read as a rejection.
//
// The shape mirrors `ConstraintDiagnostic` (§9.1), which already solved the
// same problem for the constraint solver: a stable machine-readable
// discriminator plus a human message.

import { isField } from "./utils.js";
import type {
  Constraint,
  Container,
  Expr,
  Field,
  Packet,
  Subfield,
} from "./types.js";

/** Which §11.4 row produced a warning. Stable — safe to switch on or suppress. */
export type LintRule =
  | "version-undeclared"
  | "constraint-in-recursive-def"
  | "checksum-params-override-named-crc"
  | "subfield-mask"
  | "le-bits-group";

export type LintWarning = {
  rule: LintRule;
  message: string;
};

/** §11.4: named CRC algorithms whose parameters are already well known. */
const WELL_KNOWN_CRC: ReadonlySet<string> = new Set(["crc32", "crc32c", "crc16"]);

/* -------------------------------------------------------------------------
 * helpers
 * ---------------------------------------------------------------------- */

/** Decode a §12 mask (non-negative integer or `0x…` string); undefined if malformed. */
function decodeMask(mask: unknown): bigint | undefined {
  if (typeof mask === "number") {
    if (!Number.isInteger(mask) || mask < 0) return undefined;
    return BigInt(mask);
  }
  if (typeof mask === "string" && /^0x[0-9A-Fa-f]+$/.test(mask)) return BigInt(mask);
  return undefined;
}

/** Every `ref` target reachable in `fields`, without descending into defs. */
function refTargets(fields: readonly Container[], out: Set<string>): void {
  for (const c of fields) {
    if (isField(c)) continue;
    switch (c.kind) {
      case "ref": out.add(c.ref); break;
      case "group": refTargets(c.children, out); break;
      case "bounded": refTargets(c.fields, out); break;
      case "optional": refTargets([c.container], out); break;
      case "repeat": refTargets(c.element.fields, out); break;
      case "encrypted": refTargets(c.plaintext.fields, out); break;
      case "switch": for (const arm of Object.values(c.cases)) refTargets(arm.fields, out); break;
    }
  }
}

/** Def names that reach themselves through any chain of `ref`s. */
function recursiveDefNames(packet: Packet): Set<string> {
  const defs = packet.defs ?? {};
  const edges = new Map<string, Set<string>>();
  for (const [name, def] of Object.entries(defs)) {
    const targets = new Set<string>();
    refTargets(def.fields, targets);
    edges.set(name, targets);
  }
  const recursive = new Set<string>();
  for (const start of edges.keys()) {
    const seen = new Set<string>();
    const stack = [start];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      for (const next of edges.get(cur) ?? []) {
        if (next === start) { recursive.add(start); stack.length = 0; break; }
        if (!seen.has(next)) { seen.add(next); stack.push(next); }
      }
    }
  }
  return recursive;
}

/** Instantiation ids in `body` whose `ref` target is a recursive def. */
function recursiveInstantiationIds(packet: Packet): Set<string> {
  const recursive = recursiveDefNames(packet);
  const ids = new Set<string>();
  if (recursive.size === 0) return ids;
  const walk = (fields: readonly Container[]): void => {
    for (const c of fields) {
      if (isField(c)) continue;
      switch (c.kind) {
        case "ref": if (recursive.has(c.ref) && c.id) ids.add(c.id); break;
        case "group": walk(c.children); break;
        case "bounded": walk(c.fields); break;
        case "optional": walk([c.container]); break;
        case "repeat": walk(c.element.fields); break;
        case "encrypted": walk(c.plaintext.fields); break;
        case "switch": for (const arm of Object.values(c.cases)) walk(arm.fields); break;
      }
    }
  };
  walk(packet.body);
  return ids;
}

/** Field ids named by any `ref` inside an expression. */
function exprRefIds(e: Expr, out: Set<string>): void {
  const v = e as unknown as Record<string, unknown>;
  if (v.kind === "ref" && typeof v.field === "string") out.add(v.field);
  for (const child of Object.values(v)) {
    if (child && typeof child === "object") {
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c === "object") exprRefIds(c as Expr, out);
      } else {
        exprRefIds(child as Expr, out);
      }
    }
  }
}

/** Walk every field in the body, with the byteOrder in force at that point. */
function walkFields(
  fields: readonly Container[],
  byteOrder: "BE" | "LE" | undefined,
  visit: (run: Field[], byteOrder: "BE" | "LE" | undefined) => void,
): void {
  // A "bits run" is consecutive sibling leaf fields; a non-field breaks it.
  let run: Field[] = [];
  const flush = (): void => { if (run.length > 0) { visit(run, byteOrder); run = []; } };
  for (const c of fields) {
    if (isField(c)) { run.push(c); continue; }
    flush();
    const bo = (c as { byteOrder?: "BE" | "LE" }).byteOrder ?? byteOrder;
    switch (c.kind) {
      case "group": walkFields(c.children, bo, visit); break;
      case "bounded": walkFields(c.fields, bo, visit); break;
      case "optional": walkFields([c.container], bo, visit); break;
      case "repeat": walkFields(c.element.fields, bo, visit); break;
      case "encrypted": walkFields(c.plaintext.fields, bo, visit); break;
      case "switch": for (const arm of Object.values(c.cases)) walkFields(arm.fields, bo, visit); break;
    }
  }
  flush();
}

/* -------------------------------------------------------------------------
 * rules
 * ---------------------------------------------------------------------- */

/**
 * §11.4 load-time lint. Advisory only — none of these makes a document invalid,
 * and `validatePacket` reports none of them.
 *
 * Returns warnings in rule order, then document order within a rule.
 */
export function lintPacket(packet: Packet): LintWarning[] {
  const out: LintWarning[] = [];
  const warn = (rule: LintRule, message: string): void => { out.push({ rule, message }); };

  // 1. version absent
  if (packet.version === undefined) {
    warn("version-undeclared",
      "Packet has no `version`; tools cannot tell which PSDL revision it targets (§11.4/§15).");
  }

  // 2. constraint reaching into a recursive def expansion
  const recursiveIds = recursiveInstantiationIds(packet);
  if (recursiveIds.size > 0 && packet.constraints) {
    packet.constraints.forEach((c: Constraint, i: number) => {
      const refs = new Set<string>();
      exprRefIds(c.lhs, refs);
      exprRefIds(c.rhs, refs);
      for (const r of refs) {
        const head = r.includes(".") ? r.slice(0, r.indexOf(".")) : r;
        if (recursiveIds.has(head)) {
          warn("constraint-in-recursive-def",
            `constraints[${i}] references "${r}", which lives inside the recursive def expansion "${head}"; the constraint will be silently skipped (§11.4).`);
          break;
        }
      }
    });
  }

  // 3-5. per-field rules
  walkFields(packet.body, packet.byteOrder, (run, byteOrder) => {
    for (const f of run) {
      // 3. checksumParams overriding a well-known named CRC
      if (f.checksumParams !== undefined &&
          typeof f.checksumAlgorithm === "string" &&
          WELL_KNOWN_CRC.has(f.checksumAlgorithm)) {
        warn("checksum-params-override-named-crc",
          `${f.id}: checksumParams overrides the well-known "${f.checksumAlgorithm}" parameters, which changes the effective algorithm; consider a custom algorithm name instead (§11.4/§8).`);
      }
      // 4. subfield masks: zero, or overlapping a previous one
      if (Array.isArray(f.subfields)) {
        let union = 0n;
        f.subfields.forEach((sf: Subfield, i: number) => {
          const m = decodeMask(sf.mask);
          if (m === undefined) return; // malformed: validatePacket already errors
          if (m === 0n) {
            warn("subfield-mask",
              `${f.id}: subfields[${i}] ("${sf.id}") has mask 0, so it selects no bits (§11.4/§12).`);
            return;
          }
          if ((union & m) !== 0n) {
            warn("subfield-mask",
              `${f.id}: subfields[${i}] ("${sf.id}") overlaps an earlier subfield mask (§11.4/§12).`);
          }
          union |= m;
        });
      }
    }
    // 5. a multi-field `bits` run under LE
    if (byteOrder === "LE") {
      const bitsRun = run.filter((f) => f.type.kind === "bits");
      const first = bitsRun[0];
      const last = bitsRun[bitsRun.length - 1];
      if (first !== undefined && last !== undefined && bitsRun.length >= 2) {
        warn("le-bits-group",
          `${first.id}…${last.id}: a ${bitsRun.length}-field sequential bits group under byteOrder LE is packed MSB-first and will mis-pack an LSB-first word; consider one \`int\` with \`subfields\` masks over the decoded value (§11.4/§12).`);
      }
    }
  });

  return out;
}
