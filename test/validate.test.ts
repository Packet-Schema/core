import { describe, expect, it } from "vitest";
import { validatePacket } from "../src/validate.js";
import type { Packet } from "../src/types.js";

const msgs = (pkt: Packet): string[] => validatePacket(pkt).map((e) => e.message);

describe("validatePacket — structure", () => {
  it("accepts a minimal valid packet", () => {
    expect(validatePacket({ name: "t", body: [] })).toEqual([]);
  });
  it("rejects a bad field id", () => {
    const e = msgs({ name: "t", body: [{ id: "1bad", name: "X", type: { kind: "int", bits: 8 } }] });
    expect(e.some((m) => /must match/.test(m))).toBe(true);
  });
  it("rejects a field id containing a dot", () => {
    const e = msgs({ name: "t", body: [{ id: "a.b", name: "X", type: { kind: "int", bits: 8 } }] });
    expect(e.some((m) => /must match/.test(m))).toBe(true);
  });
});

describe("validatePacket — expression placement", () => {
  it("rejects peek in bytes.n", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "d", name: "D", type: { kind: "bytes", n: { kind: "peek", bits: 8 } } }],
    });
    expect(e.some((m) => /peek may not appear in bytes\.n/.test(m))).toBe(true);
  });
  it("allows peek in optional.when", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "optional",
        when: { kind: "peek", bits: 8 },
        container: { id: "x", name: "X", type: { kind: "int", bits: 8 } },
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects enclosingField outside constraints", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "d", name: "D", type: { kind: "bytes", n: { kind: "enclosingField", field: "len" } } }],
    });
    expect(e.some((m) => /enclosingField may only appear in constraints/.test(m))).toBe(true);
  });
  it("allows enclosingField in constraints", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "d", name: "D", type: { kind: "int", bits: 8 } }],
      constraints: [{ lhs: { kind: "ref", field: "d" }, rhs: { kind: "enclosingField", field: "len" } }],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — switch keys", () => {
  it("accepts decimal/range/list/_ keys", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "switch", id: "sw", on: { kind: "lit", value: 1 },
        cases: {
          "6": { id: "a", fields: [] },
          "0-9": { id: "b", fields: [] },
          "1,2,3": { id: "c", fields: [] },
          _: { id: "d", fields: [] },
        },
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects a malformed switch key", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "switch", id: "sw", on: { kind: "lit", value: 1 },
        cases: { "0x6": { id: "a", fields: [] } },
      }],
    });
    expect(e.some((m) => /invalid switch case key/.test(m))).toBe(true);
  });
});

describe("validatePacket — lookup table keys/values (§4, §11.1)", () => {
  const lookupPkt = (table: Record<string, number>): Packet => ({
    name: "t",
    body: [{ id: "d", name: "D", type: { kind: "bytes", n: { kind: "lookup", key: { kind: "ref", field: "k" }, table } } }],
  });
  it("accepts a table with non-negative decimal keys and values", () => {
    expect(validatePacket(lookupPkt({ "0": 1, "5": 10 }))).toEqual([]);
  });
  it("rejects a negative key", () => {
    expect(msgs(lookupPkt({ "-1": 5 })).length).toBeGreaterThan(0);
  });
  it("rejects a non-integer / non-decimal key", () => {
    expect(msgs(lookupPkt({ "01": 5 })).length).toBeGreaterThan(0);
    expect(msgs(lookupPkt({ x: 5 } as Record<string, number>)).length).toBeGreaterThan(0);
  });
  it("rejects a negative value", () => {
    expect(msgs(lookupPkt({ "0": -3 })).length).toBeGreaterThan(0);
  });
});

describe("validatePacket — remaining/enclosingBits placement (§11.1)", () => {
  it("allows remaining/enclosingBits at the top-level body", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "d", name: "D", type: { kind: "bytes", n: { kind: "remaining" } } },
      ],
    });
    expect(e).toEqual([]);
  });
  it("allows remaining inside a bounded scope", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "bounded", id: "b", bytes: { kind: "lit", value: 8 },
        fields: [{ id: "d", name: "D", type: { kind: "bytes", n: { kind: "remaining" } } }],
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects remaining/enclosingBits inside an encrypted.plaintext without wireBits", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "encrypted", id: "enc",
        plaintext: { id: "pt", fields: [
          { id: "d", name: "D", type: { kind: "bytes", n: { kind: "remaining" } } },
        ] },
      }],
    });
    expect(e.some((m) => /'remaining' used outside a scope-providing container/.test(m))).toBe(true);
  });
  it("allows remaining inside an encrypted.plaintext with wireBits", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "encrypted", id: "enc", wireBits: { kind: "lit", value: 64 },
        plaintext: { id: "pt", fields: [
          { id: "d", name: "D", type: { kind: "bytes", n: { kind: "remaining" } } },
        ] },
      }],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — forward references (§10.1, §11.1)", () => {
  it("allows wireSize targeting a preceding closed field", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 8 } },
        { id: "len", name: "L", type: { kind: "bytes", n: { kind: "wireSize", target: "a" } } },
      ],
    });
    expect(e).toEqual([]);
  });
  it("rejects wireSize targeting a later field (forward reference)", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "len", name: "L", type: { kind: "bytes", n: { kind: "wireSize", target: "a" } } },
        { id: "a", name: "A", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(e.some((m) => /does not precede this expression in document order/.test(m))).toBe(true);
  });
  it("rejects wireSize targeting an enclosing/not-yet-closed container", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "bounded", id: "b", bytes: { kind: "lit", value: 8 },
        fields: [{ id: "d", name: "D", type: { kind: "bytes", n: { kind: "wireSize", target: "b" } } }],
      }],
    });
    expect(e.some((m) => /enclosing\/not-yet-closed container/.test(m))).toBe(true);
  });
  it("rejects a ref to a repeat id that precedes that repeat", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "n", name: "N", type: { kind: "bytes", n: { kind: "ref", field: "r" } } },
        {
          kind: "repeat", id: "r", count: { kind: "lit", value: 1 },
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] },
        },
      ],
    });
    expect(e.some((m) => /precedes that repeat in document order/.test(m))).toBe(true);
  });
  it("allows a ref to a repeat id after that repeat", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "r", count: { kind: "lit", value: 1 },
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] },
        },
        { id: "n", name: "N", type: { kind: "bytes", n: { kind: "ref", field: "r" } } },
      ],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — berLength / imports / refs", () => {
  it("rejects berLength maxBytes > 5", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "l", name: "L", type: { kind: "berLength", maxBytes: 7 } }],
    });
    expect(e.some((m) => /maxBytes must be 1–5/.test(m))).toBe(true);
  });
  it("rejects duplicate import as-prefix", () => {
    const e = msgs({
      name: "t",
      body: [],
      imports: [{ source: "a", as: "x" }, { source: "b", as: "x" }],
    });
    expect(e.some((m) => /duplicate 'as' prefix/.test(m))).toBe(true);
  });
  it("detects a non-recursive ref cycle", () => {
    const e = msgs({
      name: "t",
      body: [],
      defs: {
        a: { id: "a", fields: [{ kind: "ref", ref: "b", id: "rb" }] },
        b: { id: "b", fields: [{ kind: "ref", ref: "a", id: "ra" }] },
      },
    });
    expect(e.some((m) => /circular reference/.test(m))).toBe(true);
  });
  it("allows a cycle through a recursive def", () => {
    const e = msgs({
      name: "t",
      body: [],
      defs: {
        a: { id: "a", recursive: true, fields: [{ kind: "ref", ref: "a", id: "self" }] },
      },
    });
    expect(e).toEqual([]);
  });
  it("rejects a virtual field inside defs", () => {
    const e = msgs({
      name: "t",
      body: [],
      defs: { a: { id: "a", fields: [{ kind: "virtual", id: "v", expr: { kind: "lit", value: 1 } }] } },
    });
    expect(e.some((m) => /virtual.*forbidden inside a defs/.test(m))).toBe(true);
  });
});

describe("validatePacket — prevIter placement (§10.4, fix #5)", () => {
  it("accepts prevIter in repeat.count (not only repeat.until)", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "prevIter", field: "n" },
          element: { id: "el", fields: [{ id: "n", name: "N", type: { kind: "int", bits: 8 } }] },
        },
      ],
    });
    expect(e.filter((m) => /prevIter/.test(m))).toEqual([]);
  });

  it("accepts prevIter in repeat.until", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { until: { kind: "op", op: "==", a: { kind: "prevIter", field: "more" }, b: { kind: "lit", value: 0 } } },
          element: { id: "el", fields: [{ id: "more", name: "More", type: { kind: "int", bits: 1 } }] },
        },
      ],
    });
    expect(e.filter((m) => /prevIter/.test(m))).toEqual([]);
  });

  it("rejects prevIter outside a repeat count/until slot", () => {
    const e = msgs({
      name: "t",
      body: [
        { kind: "virtual", id: "v", expr: { kind: "prevIter", field: "x" } },
      ],
    });
    expect(e.some((m) => /prevIter may only appear in repeat\.count or repeat\.until/.test(m))).toBe(true);
  });
});
