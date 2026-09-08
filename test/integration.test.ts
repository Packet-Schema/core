import { describe, expect, it } from "vitest";
// Import through the package entry point on purpose: this file doubles as the
// public-API surface test, so dropping a re-export from src/index.ts fails here.
import {
  matchesPattern,
  normalize,
  resolveValueEntry,
  validateConstraints,
  validatePacket,
} from "../src/index.js";
import type {
  ConstraintDiagnostic,
  NormativeLevel,
  Packet,
  RfcRef,
  ValueEntry,
} from "../src/index.js";

// The headline §5.3/§5.4 example end-to-end: the IPv4 ToS octet read as
// DSCP (6) + ECN (2), with multi-layer provenance, value dictionary, the
// experimental pattern pool, and per-group meta — validated, normalized, and
// reverse-looked-up exactly as an LSP/renderer would.
const ipv4Tos: Packet = {
  name: "ipv4-tos",
  body: [
    {
      kind: "group",
      id: "tos",
      name: "Differentiated Services",
      meta: { rfc: { defined: 791, updates: [2474, 3168] }, section: "1.4" },
      children: [
        {
          id: "dscp",
          name: "DSCP",
          type: { kind: "int", bits: 6 },
          meta: { rfc: { defined: 2474, updates: [3260, 8622] }, section: "3" },
          values: [
            {
              value: 0,
              name: "CS0",
              label: "Default / Best Effort",
              level: "should",
            },
            {
              value: 46,
              name: "EF",
              label: "Expedited Forwarding",
              meta: { rfc: 3246 },
            },
            { range: [8, 8], name: "CS1", meta: { rfc: 2474 } },
            {
              pattern: "xxxx11",
              name: "EXP",
              label: "Experimental / Local Use",
              level: "may",
              meta: { rfc: 2474, section: "6" },
            },
          ],
        },
        {
          id: "ecn",
          name: "ECN",
          type: { kind: "int", bits: 2 },
          meta: { rfc: { defined: 3168 } },
          values: [
            { value: 0, name: "Not-ECT" },
            { value: 3, name: "CE", level: "must" },
          ],
        },
      ],
    },
  ],
};

describe("integration — IPv4 ToS (DSCP+ECN) value dictionary (§5.3/§5.4)", () => {
  it("validates with no errors", () => {
    expect(validatePacket(ipv4Tos)).toEqual([]);
  });

  it("carries values + per-group provenance through normalize", () => {
    const fs = normalize(ipv4Tos).fields;
    const dscp = fs.find((f) => f.id === "dscp")!;
    expect(dscp.values?.length).toBe(4);
    expect(dscp.groupMeta).toEqual({
      rfc: { defined: 791, updates: [2474, 3168] },
      section: "1.4",
    });
  });

  it("reverse-looks-up observed DSCP values like an LSP would", () => {
    const dscp = normalize(ipv4Tos).fields.find((f) => f.id === "dscp")!;
    const v = dscp.values!;
    expect(resolveValueEntry(v, 46)?.name).toBe("EF"); // exact
    expect(resolveValueEntry(v, 8)?.name).toBe("CS1"); // range
    expect(resolveValueEntry(v, 43)?.name).toBe("EXP"); // 0b101011 → pattern xxxx11
    expect(resolveValueEntry(v, 0)?.name).toBe("CS0"); // exact wins over pattern
    expect(resolveValueEntry(v, 10)).toBeUndefined(); // out-of-list, still valid
    // normative strength reaches the tool for badge rendering
    expect(resolveValueEntry(v, 43)?.level).toBe("may");
  });
});

// D1: a `body: []` def-only library document parses/validates and normalizes to
// zero fields. The predicate for "library" is exactly body.length === 0; a
// document with a non-empty body that normalizes to zero fields (a virtual-only
// body, body.length > 0) is NOT a library.
describe("integration — body: [] def-only library (§1.2, D1)", () => {
  const lib: Packet = {
    version: "0.5",
    name: "common-addresses",
    description: "Shared address structs (def-only library)",
    body: [],
    defs: {
      ipv4Addr: {
        id: "ipv4Addr",
        doc: "32-bit IPv4 address stored as four consecutive octets",
        fields: [
          { id: "oct0", name: "Octet 0", type: { kind: "int", bits: 8 } },
          { id: "oct1", name: "Octet 1", type: { kind: "int", bits: 8 } },
        ],
      },
      macAddr: {
        id: "macAddr",
        fields: [{ id: "b0", name: "Byte 0", type: { kind: "int", bits: 8 } }],
      },
    },
  };

  it("a body: [] + defs library validates with no errors", () => {
    expect(validatePacket(lib)).toEqual([]);
  });

  it("normalizes to zero fields (the def is not expanded without a ref)", () => {
    const norm = normalize(lib);
    expect(norm.fields).toEqual([]);
    expect(norm.totalBits).toBe(0);
    // The library identity predicate is body.length === 0.
    expect(lib.body.length).toBe(0);
  });

  it("a virtual-only body (body.length > 0) is NOT a library even though it normalizes to 0 wire bits", () => {
    const virtualOnly: Packet = {
      version: "0.5",
      name: "virtual-only",
      body: [{ kind: "virtual", id: "v", expr: { kind: "lit", value: 1 } }],
    };
    expect(validatePacket(virtualOnly)).toEqual([]);
    // body has length 1 → NOT a def library by the body.length === 0 predicate.
    expect(virtualOnly.body.length).toBe(1);
    const norm = normalize(virtualOnly);
    // It emits one (zero-width) virtual normalized field, i.e. it is not empty.
    expect(norm.fields.length).toBe(1);
    expect(norm.fields[0]!.virtual).toBe(true);
  });
});

describe("integration — public API surface (src/index.ts re-exports)", () => {
  it("exposes the §5.3/§5.4/§9.1 additions from the package entry point", () => {
    // Values of the newly exported types, typed through the index re-exports.
    const level: NormativeLevel = "should";
    const rfc: RfcRef = { defined: 2474, updates: [3260] };
    const entry: ValueEntry = { value: 46, name: "EF", level, meta: { rfc } };
    expect(resolveValueEntry([entry], 46)).toBe(entry);
    expect(matchesPattern("xxxx11", 7)).toBe(true);
    const r = validateConstraints(
      [
        {
          lhs: { kind: "lit", value: 0 },
          rhs: { kind: "lit", value: 1 },
          level: "should",
        },
      ],
      new Map(),
    );
    expect("ok" in r).toBe(true);
    const diags: ConstraintDiagnostic[] =
      "ok" in r ? (r.diagnostics ?? []) : [];
    expect(diags).toEqual([
      { index: 0, level: "should", message: "Constraint failed: lhs=0 rhs=1" },
    ]);
  });
});
