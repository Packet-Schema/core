import { walkExpr } from "./expr.js";
import { isField } from "./utils.js";
import type { Container, Expr, Packet } from "./types.js";

function isExpr(value: unknown): value is Expr {
  return typeof value === "object" && value !== null && "kind" in value &&
    typeof (value as Record<string, unknown>).kind === "string";
}

function isUntilCount(value: unknown): value is { until: Expr } {
  return typeof value === "object" && value !== null && "until" in value &&
    isExpr((value as Record<string, unknown>).until);
}

/** All plain field-id references reachable from a packet's expressions. */
export function collectPsdlRefs(packet: Packet): Set<string> {
  const out = new Set<string>();
  const visit = (e: Expr): void => {
    walkExpr(e, (n) => {
      if (n.kind === "ref") out.add(n.field);
    });
  };
  const walk = (containers: Container[]): void => {
    for (const c of containers) {
      if (isField(c)) {
        // A delimiter-terminated bytes length (`delimiter` form, §3) carries no Expr.
        if (c.type.kind === "bytes" && isExpr(c.type.n)) visit(c.type.n);
        if (c.computedFrom) visit(c.computedFrom);
        continue;
      }
      switch (c.kind) {
        case "virtual": visit(c.expr); break;
        case "group": walk(c.children); break;
        case "bounded": visit(c.bytes); walk(c.fields); break;
        case "switch":
          visit(c.on);
          for (const arm of Object.values(c.cases)) walk(arm.fields);
          break;
        case "repeat":
          if (isExpr(c.count)) visit(c.count);
          else if (isUntilCount(c.count)) visit(c.count.until);
          walk(c.element.fields);
          break;
        case "encrypted":
          if (c.wireBits) visit(c.wireBits);
          walk(c.plaintext.fields);
          break;
        case "optional":
          visit(c.when);
          walk([c.container]);
          break;
        // align, ref: no inline field-id expressions
      }
    }
  };
  walk(packet.body);
  if (packet.defs) for (const def of Object.values(packet.defs)) walk(def.fields);
  for (const con of packet.constraints ?? []) { visit(con.lhs); visit(con.rhs); }
  return out;
}
