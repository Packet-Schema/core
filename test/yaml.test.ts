import { describe, expect, it } from "vitest";
import { parsePsdl, stringifyPsdl } from "../src/yaml.js";
import type { Packet } from "../src/types.js";

describe("parsePsdl — shorthand normalization", () => {
  it("expands bare-int and bare-string expression shorthands", () => {
    const src = `
name: t
body:
  - id: len
    name: Len
    type: { kind: int, bits: 8 }
  - id: data
    name: Data
    type: { kind: bytes, n: len }
`;
    const r = parsePsdl(src);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const data = r.packet.body[1] as { type: { n: unknown } };
    expect(data.type.n).toEqual({ kind: "ref", field: "len" });
  });

  it("normalizes a bare int in repeat.count", () => {
    const src = `
name: t
body:
  - kind: repeat
    id: r
    count: 4
    element:
      id: el
      fields:
        - id: x
          name: X
          type: { kind: int, bits: 8 }
`;
    const r = parsePsdl(src);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rep = r.packet.body[0] as { count: unknown };
    expect(rep.count).toEqual({ kind: "lit", value: 4 });
  });

  it("preserves the eos sentinel and the remaining bytes length", () => {
    // §3: there is no `auto` sugar; "all remaining bytes" is written explicitly
    // as n: { kind: remaining } (finding #13 — schema/spec are the source of truth).
    const src = `
name: t
body:
  - kind: repeat
    id: r
    count: eos
    element:
      id: el
      fields:
        - id: x
          name: X
          type: { kind: bytes, n: { kind: remaining } }
`;
    const r = parsePsdl(src);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rep = r.packet.body[0] as {
      count: unknown;
      element: { fields: { type: { n: unknown } }[] };
    };
    expect(rep.count).toBe("eos");
    expect(rep.element.fields[0]!.type.n).toEqual({ kind: "remaining" });
  });

  it("reports validation errors", () => {
    const r = parsePsdl(
      `name: t\nbody:\n  - id: "1bad"\n    name: X\n    type: { kind: int, bits: 8 }`,
    );
    expect(r.ok).toBe(false);
  });
});

describe("stringifyPsdl — round-trip (export → re-parse)", () => {
  it("round-trips values (value/range/pattern incl. digit-only patterns), meta.rfc, and constraint level", () => {
    const original: Packet = {
      version: "0.5",
      name: "t",
      meta: { rfc: { defined: 791, updates: [2474, 3168] }, section: "1.4" },
      body: [
        {
          id: "dscp",
          name: "DSCP",
          type: { kind: "int", bits: 6 },
          meta: { rfc: { defined: 2474, updates: [3260] } },
          values: [
            {
              value: 46,
              name: "EF",
              label: "Expedited Forwarding",
              level: "must",
            },
            { range: [8, 15], name: "CS", level: "should" },
            // Digit-only patterns MUST survive as strings: an unquoted `pattern: 11`
            // would re-parse as the number 11 and fail validation.
            { pattern: "11", name: "EXP2" },
            { pattern: "0110", name: "EXP4", meta: { rfc: 2474 } },
          ],
        },
      ],
      constraints: [
        {
          lhs: { kind: "ref", field: "dscp" },
          rhs: { kind: "lit", value: 46 },
          level: "should",
          doc: "advisory",
        },
      ],
    };
    const reparsed = parsePsdl(stringifyPsdl(original));
    expect(reparsed.ok).toBe(true);
    if (!reparsed.ok) return;
    expect(reparsed.packet).toEqual(original);
  });

  it("round-trips enum variant objects (numeric-string keys, level/meta), ValueEntry.doc, and Group.meta", () => {
    const original: Packet = {
      version: "0.5",
      name: "t",
      body: [
        {
          kind: "group",
          id: "g",
          name: "G",
          meta: { rfc: { defined: 791, updates: [2474] }, section: "3.1" },
          children: [
            {
              id: "proto",
              name: "Protocol",
              // Mixed string/object variants under numeric-string keys: the
              // object form's level/meta must survive export → re-parse.
              type: {
                kind: "enum",
                bits: 8,
                variants: {
                  "6": {
                    label: "TCP",
                    doc: "Transmission Control",
                    level: "may",
                    meta: { rfc: 793 },
                  },
                  "17": "UDP",
                },
              },
              values: [
                {
                  value: 6,
                  name: "TCP",
                  doc: "assigned by IANA",
                  level: "should",
                },
              ],
            },
          ],
        },
      ],
    };
    const reparsed = parsePsdl(stringifyPsdl(original));
    expect(reparsed.ok).toBe(true);
    if (!reparsed.ok) return;
    expect(reparsed.packet).toEqual(original);
  });
});
