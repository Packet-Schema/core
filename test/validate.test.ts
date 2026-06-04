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
