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
  it("rejects peek bits outside 1-64 as a malformed expression (§4/§11.1, D2)", () => {
    // peek bits 0 and 65 are out of the 1-64 domain; isValidExpr returns false
    // for them, so they surface as a malformed expression in their slot. (No
    // dedicated message is emitted; the well-formedness layer rejects them.)
    for (const bad of [0, 65]) {
      const e = msgs({
        name: "t",
        body: [{
          kind: "switch", id: "s", on: { kind: "peek", bits: bad },
          cases: { "0": { id: "a", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] } },
        }],
      });
      expect(e.some((m) => /invalid discriminator expression/.test(m))).toBe(true);
    }
    // Valid boundaries 1 and 64 are accepted.
    for (const good of [1, 64]) {
      const e = msgs({
        name: "t",
        body: [{
          kind: "switch", id: "s", on: { kind: "peek", bits: good },
          cases: { "0": { id: "a", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] } },
        }],
      });
      expect(e).toEqual([]);
    }
  });
  it("validates a 64-bit display field alongside small-width expressions (§4 value domain, D2)", () => {
    // A 64-bit field is a display value, not an expression input; using a small
    // 16-bit length field in bytes.n keeps the expression within the exact range.
    const e = msgs({
      name: "t",
      body: [
        { id: "seq64", name: "Sequence Number", type: { kind: "int", bits: 64 }, display: "dec" },
        { id: "payloadLen", name: "Payload Length", type: { kind: "int", bits: 16 } },
        { id: "payload", name: "Payload", type: { kind: "bytes", n: { kind: "ref", field: "payloadLen" } } },
      ],
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
    body: [
      // `k` must be declared so the lookup's ref target exists (§D11); the test
      // exercises the lookup table key/value rules, not ref existence.
      { id: "k", name: "K", type: { kind: "int", bits: 8 } },
      { id: "d", name: "D", type: { kind: "bytes", n: { kind: "lookup", key: { kind: "ref", field: "k" }, table } } },
    ],
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

  it("allows a leaf ref to a preceding field (backward)", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "len", name: "L", type: { kind: "int", bits: 8 } },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "len" } } },
      ],
    });
    expect(e).toEqual([]);
  });

  it("rejects a leaf ref to a later field (forward, §10.1)", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "len" } } },
        { id: "len", name: "L", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(e.some((m) => /ref target "len" does not precede this expression in document order/.test(m))).toBe(true);
  });

  it("rejects a self-size ref (a field's bytes.n referencing its own id, §10.1)", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "self", name: "Self", type: { kind: "bytes", n: { kind: "ref", field: "self" } } },
      ],
    });
    expect(e.some((m) => /ref target "self" does not precede this expression in document order, or refers to its own container/.test(m))).toBe(true);
  });

  it("rejects a forward leaf ref in optional.when, switch.on, bounded.bytes, and virtual.expr", () => {
    const when = msgs({
      name: "t",
      body: [
        { kind: "optional", when: { kind: "ref", field: "flag" }, container: { id: "x", name: "X", type: { kind: "int", bits: 8 } } },
        { id: "flag", name: "Flag", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(when.some((m) => /does not precede this expression in document order/.test(m))).toBe(true);
    const on = msgs({
      name: "t",
      body: [
        { kind: "switch", id: "s", on: { kind: "ref", field: "tag" }, cases: { _: { id: "d", fields: [] } } },
        { id: "tag", name: "Tag", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(on.some((m) => /does not precede this expression in document order/.test(m))).toBe(true);
    const bnd = msgs({
      name: "t",
      body: [
        { kind: "bounded", id: "b", bytes: { kind: "ref", field: "blen" }, fields: [] },
        { id: "blen", name: "BLen", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(bnd.some((m) => /does not precede this expression in document order/.test(m))).toBe(true);
    const vrt = msgs({
      name: "t",
      body: [
        { kind: "virtual", id: "v", expr: { kind: "ref", field: "w" } },
        { id: "w", name: "W", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(vrt.some((m) => /does not precede this expression in document order/.test(m))).toBe(true);
  });

  it("allows a dotted ref-expanded target declared earlier (src.oct0), forward-check aware of subtree ids", () => {
    const def = { addr: { id: "addr", fields: [{ id: "oct0", name: "Octet 0", type: { kind: "int" as const, bits: 8 } }] } };
    const e = msgs({
      name: "t",
      defs: def,
      body: [
        { kind: "ref", ref: "addr", id: "src", name: "Source" },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "src.oct0" } } },
      ],
    });
    expect(e).toEqual([]);
  });

  // §10.7 carve-out: an ordinary `ref` from `repeat.count`/`repeat.count.until`
  // to a field of the SAME repeat's element resolves to the just-completed
  // iteration's value and is exempt from the §10.1 forward-reference rule. These
  // four pins lock the carve-out (positive) and its scope (negative).
  it("allows repeat.count.until ordinary ref to an element field (§10.7)", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "rep", count: { until: { kind: "ref", field: "more" } },
          element: { id: "el", fields: [
            { id: "more", name: "More", type: { kind: "int", bits: 1 } },
            { id: "val", name: "Val", type: { kind: "int", bits: 7 } },
          ] },
        },
      ],
    } as unknown as Packet);
    expect(e).toEqual([]);
  });

  it("allows the §10.7 `tsn != prevIter(tsn)+1` idiom in repeat.count.until", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "rep",
          count: { until: {
            kind: "op", op: "!=",
            a: { kind: "ref", field: "tsn" },
            b: { kind: "op", op: "+", a: { kind: "prevIter", field: "tsn" }, b: { kind: "lit", value: 1 } },
          } },
          element: { id: "el", fields: [
            { id: "tsn", name: "TSN", type: { kind: "int", bits: 16 } },
          ] },
        },
      ],
    } as unknown as Packet);
    expect(e).toEqual([]);
    expect(e.some((m) => /does not precede/.test(m))).toBe(false);
  });

  it("allows repeat.count (non-until) ordinary ref to an element field (§10.7)", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "rep", count: { kind: "ref", field: "n" },
          element: { id: "el", fields: [
            { id: "n", name: "N", type: { kind: "int", bits: 8 } },
          ] },
        },
      ],
    } as unknown as Packet);
    expect(e).toEqual([]);
  });

  it("keeps the §10.7 carve-out scoped: count.until ref to a LATER non-element sibling (and the repeat's own id) still errors", () => {
    // A later top-level sibling is NOT in element.fields, so the element-only
    // exempt set does not cover it: the forward-reference error must stand even
    // though the carve-out applies to the same slot.
    const later = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "rep", count: { until: { kind: "ref", field: "sibOnly" } },
          element: { id: "el", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
        },
        { id: "sibOnly", name: "SibOnly", type: { kind: "int", bits: 8 } },
      ],
    } as unknown as Packet);
    expect(later.some((m) => /does not precede this expression in document order|precedes that repeat/.test(m))).toBe(true);
    // A self-ref to the repeat's OWN container id is excluded from the exempt
    // set (built from element.fields, not the container), so it still errors.
    const ownId = msgs({
      name: "t",
      body: [
        {
          kind: "repeat", id: "rep", count: { kind: "ref", field: "rep" },
          element: { id: "el", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
        },
      ],
    } as unknown as Packet);
    expect(ownId.some((m) => /does not precede this expression in document order|precedes that repeat/.test(m))).toBe(true);
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

  it("rejects a surplus key on the repeat count until-object (mirrors schema additionalProperties:false)", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { until: { kind: "lit", value: 0 }, foo: 9 } as never,
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] },
        },
      ],
    });
    expect(e.some((m) => /repeat count until-object accepts only the "until" key \(got "foo"\)/.test(m))).toBe(true);
  });
});

describe("validatePacket — value dictionaries (§5.3)", () => {
  it("accepts a well-formed values array", () => {
    const e = msgs({ name: "t", body: [{
      id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
      values: [
        { value: 46, name: "EF", label: "Expedited Forwarding", level: "must" },
        { range: [8, 8], name: "CS1", meta: { rfc: 2474 } },
      ],
    }] });
    expect(e).toEqual([]);
  });
  it("accepts a values entry whose meta.rfc is the multi-layer object form", () => {
    const e = msgs({ name: "t", body: [{
      id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
      values: [{ value: 0, name: "CS0", meta: { rfc: { defined: 2474, updates: [3260, 8622] } } }],
    }] });
    expect(e).toEqual([]);
  });
  it("rejects an entry with both value and range", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ value: 1, range: [2, 3] }],
    }] });
    expect(e.some((m) => /exactly one of 'value'/.test(m))).toBe(true);
  });
  it("rejects an entry with neither value nor range", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [{ name: "x" }],
    }] });
    expect(e.some((m) => /exactly one of 'value'/.test(m))).toBe(true);
  });
  it("rejects a malformed range (min > max)", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [{ range: [5, 2] }],
    }] });
    expect(e.some((m) => /range must be/.test(m))).toBe(true);
  });
  it("rejects a range with the wrong arity (matches the schema's minItems/maxItems: 2)", () => {
    expect(msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [{ range: [8] as never }],
    }] }).some((m) => /range must be/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [{ range: [1, 2, 8] as never }],
    }] }).some((m) => /range must be/.test(m))).toBe(true);
  });
  it("rejects a non-integer value (§5.3)", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [{ value: 4.6 }],
    }] });
    expect(e.some((m) => /value must be an integer/.test(m))).toBe(true);
  });
  it("rejects non-string name/label/doc (matches the schema's type: string, e.g. YAML `name: 404`)", () => {
    const e = msgs({ name: "t", body: [{
      id: "status", name: "Status", type: { kind: "int", bits: 16 },
      values: [{ value: 404, name: 404 as never, label: 0 as never, doc: ["x"] as never }],
    }] });
    expect(e.some((m) => /values\[0\]: name must be a string/.test(m))).toBe(true);
    expect(e.some((m) => /values\[0\]: label must be a string/.test(m))).toBe(true);
    expect(e.some((m) => /values\[0\]: doc must be a string/.test(m))).toBe(true);
  });
  it("rejects an invalid level on a value entry", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ value: 1, level: "required" as never }],
    }] });
    expect(e.some((m) => /invalid level/.test(m))).toBe(true);
  });
  it("accepts a pattern bit-predicate entry (§5.3)", () => {
    const e = msgs({ name: "t", body: [{
      id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
      values: [{ pattern: "xxxx11", name: "EXP", level: "may" }],
    }] });
    expect(e).toEqual([]);
  });
  it("rejects a pattern with illegal characters (§5.3)", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ pattern: "xx12" }],
    }] });
    expect(e.some((m) => /pattern must be a non-empty string/.test(m))).toBe(true);
  });
  it("rejects mixing value and pattern (§5.3)", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ value: 1, pattern: "xx11" }],
    }] });
    expect(e.some((m) => /exactly one of 'value', 'range', or 'pattern'/.test(m))).toBe(true);
  });
  it("accepts negative value/range on a signed field (§5.3)", () => {
    const e = msgs({ name: "t", body: [{
      id: "off", name: "Offset", type: { kind: "int", bits: 8, signed: true },
      values: [
        { value: -1, name: "SENTINEL" },
        { range: [-8, -1], name: "NEG_BAND" },
      ],
    }] });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — values entries must be objects (§5.3)", () => {
  it("reports (not throws on) a null values entry, e.g. YAML `values: [~]`", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [null as never],
    }] });
    expect(e.some((m) => /values\[0\] must be an object/.test(m))).toBe(true);
  });
  it("reports an undefined values entry", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: [undefined as never],
    }] });
    expect(e.some((m) => /values\[0\] must be an object/.test(m))).toBe(true);
  });
  it("reports a primitive values entry", () => {
    const e = msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 }, values: ["x" as never],
    }] });
    expect(e.some((m) => /values\[0\] must be an object/.test(m))).toBe(true);
  });
  it("reports (not throws on) a non-array values, e.g. a forgotten YAML dash", () => {
    const pkt: Packet = { name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: { value: 1, name: "A" } as never,
    }] };
    expect(() => validatePacket(pkt)).not.toThrow();
    expect(msgs(pkt).some((m) => /values must be an array/.test(m))).toBe(true);
  });
});

describe("validatePacket — meta.rfc shape (§5.4)", () => {
  const fieldWithMeta = (meta: unknown): Packet => ({
    name: "t",
    body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, meta: meta as never }],
  });
  it("accepts the bare-number and { defined, updates } forms", () => {
    expect(msgs(fieldWithMeta({ rfc: 791 }))).toEqual([]);
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [2474, 3168] } }))).toEqual([]);
    expect(msgs(fieldWithMeta({ rfc: { defined: 791 } }))).toEqual([]);
  });
  it("rejects an rfc object missing the required defined", () => {
    const e = msgs(fieldWithMeta({ rfc: { updates: [2474] } }));
    expect(e.some((m) => /meta\.rfc must be an integer or \{ defined, updates\? \}/.test(m))).toBe(true);
  });
  it("rejects a string / non-integer rfc", () => {
    expect(msgs(fieldWithMeta({ rfc: "791" })).length).toBeGreaterThan(0);
    expect(msgs(fieldWithMeta({ rfc: 791.5 })).length).toBeGreaterThan(0);
  });
  it("rejects surplus provenance keys (matches the schema's additionalProperties: false)", () => {
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, obsoletes: [760] } })).length).toBeGreaterThan(0);
  });
  it("rejects non-integer updates entries", () => {
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [1.5] } })).length).toBeGreaterThan(0);
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: "x" } })).length).toBeGreaterThan(0);
  });
  it("accepts object-form { rfc, section? } updates entries and bare+object mix (D8)", () => {
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ rfc: 2474, section: "3" }] } }))).toEqual([]);
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [2474, { rfc: 3168, section: "5" }] } }))).toEqual([]);
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ rfc: 2474 }] } }))).toEqual([]);
  });
  it("rejects malformed object-form updates entries (D8)", () => {
    // missing rfc
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ section: "3" }] } })).length).toBeGreaterThan(0);
    // surplus key
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ rfc: 2474, foo: 1 }] } })).length).toBeGreaterThan(0);
    // non-integer rfc
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ rfc: "2474" }] } })).length).toBeGreaterThan(0);
    // non-string section
    expect(msgs(fieldWithMeta({ rfc: { defined: 791, updates: [{ rfc: 2474, section: 3 }] } })).length).toBeGreaterThan(0);
  });
  it("checks packet meta, ValueEntry meta, group meta, and enum variant meta too", () => {
    expect(msgs({ name: "t", body: [], meta: { rfc: { updates: [2474] } } as never })
      .some((m) => /packet: meta\.rfc/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ value: 1, meta: { rfc: "x" } as never }],
    }] }).some((m) => /values\[0\]: meta\.rfc/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      kind: "group", id: "g", name: "G", meta: { rfc: [791] } as never,
      children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
    }] }).some((m) => /meta\.rfc/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      id: "p", name: "P",
      type: { kind: "enum", bits: 8, variants: { "6": { label: "TCP", meta: { rfc: "793" } as never } } },
    }] }).some((m) => /enum variant "6": meta\.rfc/.test(m))).toBe(true);
  });
  it("accepts meta on bounded and encrypted regions (§5.4)", () => {
    expect(msgs({ name: "t", body: [
      {
        kind: "bounded", id: "b", bytes: { kind: "lit", value: 4 }, meta: { rfc: 9000 },
        fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }],
      },
      {
        kind: "encrypted", id: "e", meta: { rfc: { defined: 9001 } },
        plaintext: { id: "pt", fields: [{ id: "y", name: "Y", type: { kind: "int", bits: 8 } }] },
      },
    ] })).toEqual([]);
  });
  it("rejects a non-object meta", () => {
    expect(msgs(fieldWithMeta(791)).some((m) => /meta must be an object/.test(m))).toBe(true);
  });
});

describe("validatePacket — enum variant keys & level (§3)", () => {
  it("rejects a non-decimal variant key", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 8, variants: { "0x6": { label: "TCP" } } as never },
    }] });
    expect(e.some((m) => /variant key .* non-negative decimal/.test(m))).toBe(true);
  });
  it("rejects an invalid level on an enum variant", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 8, variants: { "6": { label: "TCP", level: "nope" as never } } },
    }] });
    expect(e.some((m) => /invalid level/.test(m))).toBe(true);
  });
  it("accepts string and object variants together", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 8, variants: { "6": "TCP", "17": { label: "UDP", level: "may" } } },
    }] });
    expect(e).toEqual([]);
  });
  it("rejects an enum without a variants table (matches the schema's required list)", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 8 } as never,
    }] });
    expect(e.some((m) => /enum must have a variants object/.test(m))).toBe(true);
  });
  it("still accepts an empty variants table", () => {
    expect(msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 8, variants: {} },
    }] })).toEqual([]);
  });
  it("rejects a YAML-list variants (array is not a variants object, matches schema type: object)", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P", type: { kind: "enum", bits: 2, variants: ["zero", "one"] as never },
    }] });
    expect(e.some((m) => /enum must have a variants object/.test(m))).toBe(true);
  });
  it("rejects an unknown key on a variant object (matches the schema's additionalProperties: false)", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P",
      type: { kind: "enum", bits: 8, variants: { "6": { label: "TCP", name: "TCP" } as never } },
    }] });
    expect(e.some((m) => /enum variant "6" has unknown key "name"/.test(m))).toBe(true);
  });
  it("rejects a non-string variant doc (matches the schema's type: string, e.g. YAML `doc: 793`)", () => {
    const e = msgs({ name: "t", body: [{
      id: "p", name: "P",
      type: { kind: "enum", bits: 8, variants: { "6": { label: "TCP", doc: 793 as never } } },
    }] });
    expect(e.some((m) => /enum variant "6" doc must be a string/.test(m))).toBe(true);
  });
});

describe("validatePacket — meta key/shape parity with the schema (§5.4)", () => {
  const fieldWithMeta = (meta: unknown): Packet => ({
    name: "t",
    body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, meta: meta as never }],
  });
  it("rejects a non-string meta.section (e.g. unquoted YAML `section: 4.10` → number 4.1)", () => {
    const e = msgs(fieldWithMeta({ rfc: 2474, section: 4.1 }));
    expect(e.some((m) => /meta\.section must be a string/.test(m))).toBe(true);
  });
  it("rejects unknown meta keys (matches the schema's additionalProperties: false)", () => {
    expect(msgs(fieldWithMeta({ note: "x" })).some((m) => /meta has unknown key "note"/.test(m))).toBe(true);
    // typo'd "rcf" must not silently drop the provenance
    expect(msgs(fieldWithMeta({ rcf: 791 })).some((m) => /meta has unknown key "rcf"/.test(m))).toBe(true);
  });
  it("checks section/unknown keys on packet meta, ValueEntry meta, and group meta too", () => {
    expect(msgs({ name: "t", body: [], meta: { rfc: 791, section: 3.1 } as never })
      .some((m) => /packet: meta\.section must be a string/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      id: "f", name: "F", type: { kind: "int", bits: 8 },
      values: [{ value: 1, meta: { section: 4.1 } as never }],
    }] }).some((m) => /values\[0\]: meta\.section must be a string/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{
      kind: "group", id: "g", name: "G", meta: { rfc: 791, bogus: 1 } as never,
      children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
    }] }).some((m) => /meta has unknown key "bogus"/.test(m))).toBe(true);
  });
  it("packet meta additionally allows aliases (schema PacketMeta); field meta does not", () => {
    expect(msgs({ name: "t", body: [], meta: { rfc: 791, section: "3.1", aliases: ["IPv4"] } })).toEqual([]);
    expect(msgs({ name: "t", body: [], meta: { aliases: "IPv4" } as never })
      .some((m) => /meta\.aliases must be an array of strings/.test(m))).toBe(true);
    expect(msgs(fieldWithMeta({ rfc: 791, aliases: ["F"] }))
      .some((m) => /meta has unknown key "aliases"/.test(m))).toBe(true);
  });
});

describe("validatePacket — ValueEntry unknown keys (§5.3)", () => {
  it("rejects a typo'd annotation key (matches the schema's additionalProperties: false)", () => {
    const e = msgs({ name: "t", body: [{
      id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
      values: [{ value: 46, lable: "EF" } as never],
    }] });
    expect(e.some((m) => /values\[0\] has unknown key "lable"/.test(m))).toBe(true);
  });
  it("accepts every documented ValueEntry key", () => {
    expect(msgs({ name: "t", body: [{
      id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
      values: [{ value: 46, name: "EF", label: "Expedited", doc: "RFC 3246", level: "must", meta: { rfc: 3246 } }],
    }] })).toEqual([]);
  });
});

describe("validatePacket — constraint level (§9.1)", () => {
  it("rejects an invalid constraint level", () => {
    const e = validatePacket({ name: "t", body: [], constraints: [
      { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 1 }, level: "strong" as never },
    ] }).map((x) => x.message);
    expect(e.some((m) => /invalid level/.test(m))).toBe(true);
  });
  it("accepts must / should / may constraint levels", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      constraints: [
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 1 }, level: "must" },
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 1 }, level: "should" },
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 1 }, level: "may" },
      ],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — constraint keys & doc parity with the schema (§9)", () => {
  it("rejects a typo'd constraint key so it cannot silently demote a should to must (e.g. 'leval')", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      constraints: [
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 5 }, leval: "should" } as never,
      ],
    });
    expect(e.some((m) => /constraints\[0\] has unknown key "leval"/.test(m))).toBe(true);
  });
  it("rejects a non-string constraint doc (matches the schema's type: string)", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      constraints: [
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 5 }, doc: 3.1 as never },
      ],
    });
    expect(e.some((m) => /constraints\[0\]: doc must be a string/.test(m))).toBe(true);
  });
  it("accepts every documented constraint key", () => {
    expect(msgs({
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      constraints: [
        { lhs: { kind: "ref", field: "a" }, rhs: { kind: "lit", value: 5 }, doc: "RFC 793 §3.1", level: "should" },
      ],
    })).toEqual([]);
  });
});

describe("validatePacket — defs struct meta (§5.4, §6)", () => {
  const defsPacket = (meta: unknown): Packet => ({
    name: "t",
    defs: {
      foo: {
        id: "foo",
        ...(meta !== undefined ? { meta: meta as never } : {}),
        fields: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      },
    },
    body: [{ kind: "ref", ref: "foo", id: "x", name: "X" }],
  });
  it("accepts meta (bare and multi-layer rfc) on a defs struct", () => {
    expect(msgs(defsPacket({ rfc: 791 }))).toEqual([]);
    expect(msgs(defsPacket({ rfc: { defined: 791, updates: [2474] }, section: "3.1" }))).toEqual([]);
  });
  it("validates the meta shape on a defs struct like every other level", () => {
    expect(msgs(defsPacket({ rfc: "791" })).some((m) => /defs\/foo: meta\.rfc must be an integer/.test(m))).toBe(true);
    expect(msgs(defsPacket({ bogus: 1 })).some((m) => /defs\/foo: meta has unknown key "bogus"/.test(m))).toBe(true);
  });
});

// C24/§8/§11.1: `checksumParams` is only meaningful for a CRC parameter model;
// pairing it with a named non-CRC algorithm (internet, adler32) is a validation
// error. The spec規定 this row but the reference validator previously did not
// enforce it (spec-code mismatch). These tests pin the now-implemented behavior.
describe("validatePacket — checksumParams / algorithm (§8/§11.1)", () => {
  const cksum = (algorithm: string, withParams: boolean): Packet => ({
    name: "t",
    body: [{
      id: "fcs", name: "FCS", type: { kind: "int", bits: 32 }, category: "checksum",
      checksumAlgorithm: algorithm,
      ...(withParams ? { checksumParams: { polynomial: 0x04c11db7 } } : {}),
    }],
  });
  it("rejects checksumParams with the non-CRC algorithm internet", () => {
    expect(msgs(cksum("internet", true)).some((m) => /checksumParams cannot be used with the non-CRC algorithm "internet"/.test(m))).toBe(true);
  });
  it("rejects checksumParams with the non-CRC algorithm adler32", () => {
    expect(msgs(cksum("adler32", true)).some((m) => /checksumParams cannot be used with the non-CRC algorithm "adler32"/.test(m))).toBe(true);
  });
  it("accepts checksumParams with a CRC algorithm (crc32, custom name)", () => {
    expect(msgs(cksum("crc32", true))).toEqual([]);
    expect(msgs(cksum("crc32-custom", true))).toEqual([]);
  });
  it("accepts internet/adler32 when no checksumParams are present", () => {
    expect(msgs(cksum("internet", false))).toEqual([]);
    expect(msgs(cksum("adler32", false))).toEqual([]);
  });
});

// C12/§5.1/§11.1: `category` is a closed nine-token set; an unknown token is a
// validation error, mirroring the schema's CategoryToken enum. (The fact that an
// `align` container cannot carry `category` at all is enforced structurally by the
// Align type / schema additionalProperties:false, not here.)
describe("validatePacket — category token closure (§5.1)", () => {
  const cat = (category: string): Packet => ({
    name: "t",
    body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, category: category as never }],
  });
  it("accepts each of the nine category tokens", () => {
    for (const t of ["addressing", "identifier", "length", "type", "flags", "reserved", "checksum", "variable", "payload-marker"])
      expect(msgs(cat(t))).toEqual([]);
  });
  it("rejects an unknown category token", () => {
    expect(msgs(cat("checsum")).some((m) => /category "checsum" is not one of the nine category tokens/.test(m))).toBe(true);
    expect(msgs(cat("padding")).some((m) => /category "padding" is not one of the nine category tokens/.test(m))).toBe(true);
  });
});

describe("validatePacket — expanded-id collisions (§2/§11.1, D10)", () => {
  it("accepts the same field id reused across mutually-exclusive switch arms", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "protocol", name: "Protocol", type: { kind: "int", bits: 8 } },
        {
          kind: "switch", id: "payload", on: { kind: "ref", field: "protocol" },
          cases: {
            "6": { id: "tcp", fields: [{ id: "srcPort", name: "Source Port", type: { kind: "int", bits: 16 } }] },
            "17": { id: "udp", fields: [{ id: "srcPort", name: "Source Port", type: { kind: "int", bits: 16 } }] },
          },
        },
      ],
    });
    expect(e).toEqual([]);
  });

  it("rejects a flat duplicate field id", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "foo", name: "Foo", type: { kind: "int", bits: 8 } },
        { id: "foo", name: "Foo2", type: { kind: "int", bits: 8 } },
      ],
    });
    expect(e.some((m) => /expanded id "foo" is declared more than once/.test(m))).toBe(true);
  });

  it("rejects two refs sharing the same instantiation id", () => {
    const e = msgs({
      name: "t",
      body: [
        { kind: "ref", ref: "addr", id: "src", name: "Source" },
        { kind: "ref", ref: "addr", id: "src", name: "Dup" },
      ],
      defs: { addr: { id: "addr", fields: [{ id: "oct0", name: "Octet 0", type: { kind: "int", bits: 8 } }] } },
    });
    // "src" and "src.oct0" both collide.
    expect(e.some((m) => /expanded id "src(\.oct0)?" is declared more than once/.test(m))).toBe(true);
  });

  it("accepts two distinct ref instantiations sharing a bare element/field id (§6 reuse)", () => {
    const e = msgs({
      name: "t",
      body: [
        { kind: "ref", ref: "tlv", id: "first", name: "F" },
        { kind: "ref", ref: "tlv", id: "second", name: "S" },
      ],
      defs: { tlv: { id: "tlv", fields: [{ id: "len", name: "Len", type: { kind: "int", bits: 8 } }] } },
    });
    // first.len / second.len are distinct expanded ids → OK.
    expect(e).toEqual([]);
  });

  it("rejects a duplicate inside one switch arm", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "d", name: "D", type: { kind: "int", bits: 8 } },
        {
          kind: "switch", id: "s", on: { kind: "ref", field: "d" },
          cases: {
            "1": {
              id: "a",
              fields: [
                { id: "x", name: "X", type: { kind: "int", bits: 8 } },
                { id: "x", name: "X2", type: { kind: "int", bits: 8 } },
              ],
            },
          },
        },
      ],
    });
    expect(e.some((m) => /expanded id "x" is declared more than once/.test(m))).toBe(true);
  });

  it("rejects an arm field colliding with an enclosing-scope field", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "x", name: "X", type: { kind: "int", bits: 8 } },
        {
          kind: "switch", id: "s", on: { kind: "ref", field: "x" },
          cases: { "1": { id: "a", fields: [{ id: "x", name: "X2", type: { kind: "int", bits: 8 } }] } },
        },
      ],
    });
    expect(e.some((m) => /expanded id "x" is declared more than once/.test(m))).toBe(true);
  });

  it("does not flag two sibling repeats sharing an element field id (distinct namespaces)", () => {
    const e = msgs({
      name: "t",
      body: [
        { kind: "repeat", id: "r1", count: { kind: "lit", value: 2 },
          element: { id: "e1", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] } },
        { kind: "repeat", id: "r2", count: { kind: "lit", value: 2 },
          element: { id: "e2", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] } },
      ],
    });
    expect(e).toEqual([]);
  });

  it("skips import-qualified ref expansion (deferred to the import-resolving layer)", () => {
    const e = msgs({
      name: "t",
      imports: [{ source: "common/addr.psdl", as: "addr" }],
      body: [
        { kind: "ref", ref: "addr.ipv4", id: "src", name: "Source" },
        { kind: "ref", ref: "addr.ipv4", id: "dst", name: "Dest" },
      ],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — leaf ref existence (§2/§11.1, D11)", () => {
  it("rejects a typo'd ref target that is declared nowhere", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "length", name: "Length", type: { kind: "int", bits: 16 } },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "lenght" } } },
      ],
    });
    expect(e.some((m) => /ref target "lenght" is not declared anywhere/.test(m))).toBe(true);
  });

  it("accepts a correctly-spelled ref target", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "length", name: "Length", type: { kind: "int", bits: 16 } },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "length" } } },
      ],
    });
    expect(e).toEqual([]);
  });

  it("rejects a '#'-qualified id in an expression", () => {
    const e = msgs({
      name: "t",
      body: [
        { id: "length", name: "Length", type: { kind: "int", bits: 16 } },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "length#0" } } },
      ],
    });
    expect(e.some((m) => /'#'-qualified ids may not appear in expressions/.test(m))).toBe(true);
  });

  it("detects a local-ref-expanded dotted typo but accepts the correct dotted id", () => {
    const def = { addr: { id: "addr", fields: [{ id: "oct0", name: "Octet 0", type: { kind: "int" as const, bits: 8 } }] } };
    const bad = msgs({
      name: "t",
      defs: def,
      body: [
        { kind: "ref", ref: "addr", id: "src", name: "Source" },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "src.oktet0" } } },
      ],
    });
    expect(bad.some((m) => /ref target "src.oktet0" is not declared anywhere/.test(m))).toBe(true);
    const ok = msgs({
      name: "t",
      defs: def,
      body: [
        { kind: "ref", ref: "addr", id: "src", name: "Source" },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "src.oct0" } } },
      ],
    });
    expect(ok).toEqual([]);
  });

  it("skips import-qualified dotted ref targets (deferred to the import layer, §1.2)", () => {
    const e = msgs({
      name: "t",
      imports: [{ source: "common/addr.psdl", as: "addr" }],
      body: [
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "addr.ipv4.oct0" } } },
      ],
    });
    expect(e).toEqual([]);
  });

  it("checks ref existence in constraints (exempt from forward order, not from existence)", () => {
    const bad = msgs({
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      constraints: [{ lhs: { kind: "ref", field: "nope" }, rhs: { kind: "lit", value: 1 } }],
    });
    expect(bad.some((m) => /ref target "nope" is not declared anywhere/.test(m))).toBe(true);
    // A constraint may forward-reference any declared field (no document-order rule).
    const ok = msgs({
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 8 } },
        { id: "b", name: "B", type: { kind: "int", bits: 8 } },
      ],
      constraints: [{ lhs: { kind: "ref", field: "b" }, rhs: { kind: "ref", field: "a" } }],
    });
    expect(ok).toEqual([]);
  });

  it("accepts a Radiotap-style present-bitmap chain (optional.when refs a prior closed field)", () => {
    const e = msgs({
      name: "radiotap",
      body: [
        { id: "version", name: "Version", type: { kind: "int", bits: 8 }, const: 0 },
        { id: "pad", name: "Pad", type: { kind: "int", bits: 8 } },
        { id: "length", name: "Length", type: { kind: "int", bits: 16 }, category: "length" },
        { id: "present0", name: "Present 0", type: { kind: "int", bits: 32 } },
        {
          kind: "optional",
          when: { kind: "op", op: "&", a: { kind: "ref", field: "present0" }, b: { kind: "lit", value: 2147483648 } },
          container: { id: "present1", name: "Present 1", type: { kind: "int", bits: 32 } },
        },
        {
          kind: "optional",
          when: { kind: "op", op: "&", a: { kind: "ref", field: "present1" }, b: { kind: "lit", value: 2147483648 } },
          container: { id: "present2", name: "Present 2", type: { kind: "int", bits: 32 } },
        },
        { id: "fields", name: "Fields", type: { kind: "bytes", n: { kind: "remaining" } }, display: "hex" },
      ],
    });
    expect(e).toEqual([]);
  });
});

describe("validatePacket — checksumParams width & integer precision (§8/§11.1, D9)", () => {
  it("accepts a CRC-64 with hex-string params and int.bits-derived width", () => {
    const e = msgs({
      name: "t",
      body: [
        {
          id: "crc", name: "CRC-64", type: { kind: "int", bits: 64 }, category: "checksum",
          checksumAlgorithm: "crc64-ecma182", checksumCovers: ["data"],
          checksumParams: {
            polynomial: "0xAD93D23594C935A9", initValue: "0xFFFFFFFFFFFFFFFF",
            finalXOR: "0xFFFFFFFFFFFFFFFF", inputReflect: true, outputReflect: true,
          },
        },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "lit", value: 8 } } },
      ],
    });
    expect(e).toEqual([]);
  });
  it("accepts bare integers within 2^53-1 (back-compat)", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "fcs", name: "FCS", type: { kind: "int", bits: 32 }, category: "checksum",
        checksumAlgorithm: "crc32-custom",
        checksumParams: { polynomial: 0x04c11db7, initValue: 0xffffffff },
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects a bare integer above 2^53-1 (must be a hex string)", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "crc", name: "CRC", type: { kind: "int", bits: 64 }, category: "checksum",
        checksumParams: { polynomial: 0xad93d23594c935a9 },
      }],
    });
    expect(e.some((m) => /exceeds 2\^53−1 and must be written as a \^0x/.test(m))).toBe(true);
  });
  it("rejects a malformed hex-string param", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "crc", name: "CRC", type: { kind: "int", bits: 32 }, category: "checksum",
        checksumParams: { polynomial: "0xZZ" },
      }],
    });
    expect(e.some((m) => /hex string .* must match \^0x/.test(m))).toBe(true);
  });
  it("rejects checksumParams on a bytes field without an explicit width", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "crc", name: "CRC", type: { kind: "bytes", n: { kind: "lit", value: 4 } }, category: "checksum",
        checksumParams: { polynomial: 0x04c11db7 },
      }],
    });
    expect(e.some((m) => /requires an explicit width/.test(m))).toBe(true);
  });
  it("accepts checksumParams on a bytes field with an explicit width", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "crc", name: "CRC", type: { kind: "bytes", n: { kind: "lit", value: 4 } }, category: "checksum",
        checksumParams: { polynomial: 0x04c11db7, width: 32 },
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects an out-of-range width", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "crc", name: "CRC", type: { kind: "int", bits: 32 }, category: "checksum",
        checksumParams: { polynomial: 0x04c11db7, width: 65 },
      }],
    });
    expect(e.some((m) => /width must be an integer in 1–64/.test(m))).toBe(true);
  });
});

describe("validatePacket — headerProtected resolution (§5/§11.1, D6)", () => {
  it("accepts plaintext-external ids declared earlier in the same body (QUIC)", () => {
    const e = msgs({
      name: "quic",
      body: [
        { id: "firstByte", name: "First Byte", type: { kind: "int", bits: 8 } },
        { id: "packetNumber", name: "Packet Number", type: { kind: "bytes", n: { kind: "lit", value: 4 } } },
        {
          kind: "encrypted", id: "payload", wireBits: { kind: "lit", value: 800 },
          plaintext: { id: "frames", fields: [{ id: "data", name: "Data", type: { kind: "bytes", n: { kind: "remaining" } } }] },
          headerProtected: ["firstByte", "packetNumber"],
        },
      ],
    });
    expect(e).toEqual([]);
  });
  it("accepts a plaintext-internal id", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "encrypted", id: "enc", wireBits: { kind: "lit", value: 64 },
        plaintext: { id: "pt", fields: [{ id: "hdr", name: "H", type: { kind: "int", bits: 8 } }] },
        headerProtected: ["hdr"],
      }],
    });
    expect(e).toEqual([]);
  });
  it("rejects a headerProtected id resolving to neither plaintext nor an earlier same-body field", () => {
    const e = msgs({
      name: "t",
      body: [{
        kind: "encrypted", id: "enc", wireBits: { kind: "lit", value: 64 },
        plaintext: { id: "pt", fields: [{ id: "hdr", name: "H", type: { kind: "int", bits: 8 } }] },
        headerProtected: ["nope"],
      }],
    });
    expect(e.some((m) => /headerProtected id "nope" resolves to neither/.test(m))).toBe(true);
  });
});

describe("validatePacket — bytes delimiter form (§3/§11.1, D3)", () => {
  it("accepts a CRLF-terminated bytes field", () => {
    const e = msgs({
      name: "http",
      body: [{ id: "requestLine", name: "Request line", display: "ascii", type: { kind: "bytes", n: { delimiter: [13, 10] } } }],
    });
    expect(e).toEqual([]);
  });
  it("accepts a NUL-terminated bytes field", () => {
    const e = msgs({
      name: "smb",
      body: [{ id: "filename", name: "Filename", display: "ascii", type: { kind: "bytes", n: { delimiter: [0] } } }],
    });
    expect(e).toEqual([]);
  });
  it("rejects an empty delimiter array", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "x", name: "X", type: { kind: "bytes", n: { delimiter: [] } } }],
    });
    expect(e.some((m) => /delimiter must be a non-empty array/.test(m))).toBe(true);
  });
  it("rejects a delimiter byte outside 0-255", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "x", name: "X", type: { kind: "bytes", n: { delimiter: [256] } } }],
    });
    expect(e.some((m) => /delimiter elements must be integers in 0–255/.test(m))).toBe(true);
  });
  it("rejects an unknown key on the delimiter form", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "x", name: "X", type: { kind: "bytes", n: { delimiter: [0], consume: true } as never } }],
    });
    expect(e.some((m) => /delimiter form accepts only the "delimiter" key \(got "consume"\)/.test(m))).toBe(true);
  });
});

describe("validatePacket — subfields (§12/§11.1, D4)", () => {
  const fcf = (extra: Record<string, unknown> = {}) => ({
    name: "ieee802154",
    byteOrder: "LE" as const,
    body: [{
      id: "fcf", name: "Frame Control", type: { kind: "int" as const, bits: 16 }, display: "hex" as const,
      subfields: [
        { id: "frameType", name: "Frame Type", mask: 0x0007, category: "type" as const,
          values: [{ value: 1, label: "Data" }, { value: 2, label: "Ack" }] },
        { id: "secEnabled", name: "Security Enabled", mask: 0x0008, category: "flags" as const },
        { id: "srcAddrMode", name: "Src Addr Mode", mask: 0xc000, category: "type" as const },
      ],
      ...extra,
    }],
  });
  it("accepts non-overlapping subfields over an LE 16-bit int", () => {
    expect(msgs(fcf())).toEqual([]);
  });
  it("rejects subfields on a non-int / non-byte-aligned-bits field", () => {
    const e = msgs({
      name: "t",
      body: [{
        id: "x", name: "X", type: { kind: "bytes", n: { kind: "lit", value: 2 } },
        subfields: [{ id: "a", name: "A", mask: 1 }],
      }],
    });
    expect(e.some((m) => /subfields are only allowed on an int field or a byte-aligned bits field/.test(m))).toBe(true);
  });
  it("accepts subfields on a byte-aligned bits field but rejects a non-byte-aligned one", () => {
    const ok = msgs({
      name: "t",
      body: [{ id: "x", name: "X", type: { kind: "bits", n: 16 }, subfields: [{ id: "a", name: "A", mask: 0x00ff }] }],
    });
    expect(ok).toEqual([]);
    const bad = msgs({
      name: "t",
      body: [{ id: "x", name: "X", type: { kind: "bits", n: 12 }, subfields: [{ id: "a", name: "A", mask: 1 }] }],
    });
    expect(bad.some((m) => /byte-aligned bits field/.test(m))).toBe(true);
  });
  it("rejects a mask that does not fit the declared width", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, subfields: [{ id: "a", name: "A", mask: 0x100 }] }],
    });
    expect(e.some((m) => /does not fit within the field's declared 8-bit width/.test(m))).toBe(true);
  });
  it("accepts a >53-bit hex-string mask on a 64-bit field (BigInt precision)", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "f", name: "F", type: { kind: "int", bits: 64 }, subfields: [{ id: "hi", name: "Hi", mask: "0xFFFFFFFF00000000" }] }],
    });
    expect(e).toEqual([]);
  });
  it("rejects a >53-bit hex mask that overflows the declared width", () => {
    const e = msgs({
      name: "t",
      body: [{ id: "f", name: "F", type: { kind: "int", bits: 32 }, subfields: [{ id: "hi", name: "Hi", mask: "0xFFFFFFFF00000000" }] }],
    });
    expect(e.some((m) => /does not fit within the field's declared 32-bit width/.test(m))).toBe(true);
  });
  it("rejects a malformed mask and an unknown subfield key", () => {
    expect(msgs({ name: "t", body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, subfields: [{ id: "a", name: "A", mask: "ff" } as never] }] })
      .some((m) => /mask must be a non-negative integer or a \^0x/.test(m))).toBe(true);
    expect(msgs({ name: "t", body: [{ id: "f", name: "F", type: { kind: "int", bits: 8 }, subfields: [{ id: "a", name: "A", mask: 1, bogus: 1 } as never] }] })
      .some((m) => /has unknown key "bogus"/.test(m))).toBe(true);
  });
});
