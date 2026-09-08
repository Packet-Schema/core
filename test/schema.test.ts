import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";

const schemaPath = fileURLToPath(
  new URL("../schemas/psdl-0.5.yaml", import.meta.url),
);
const schema = parseYaml(readFileSync(schemaPath, "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

describe("JSON Schema — psdl-0.5.yaml", () => {
  it("compiles without error", () => {
    expect(typeof validate).toBe("function");
  });

  it("accepts a representative packet", () => {
    const pkt = {
      version: "0.5",
      name: "ipv4",
      byteOrder: "BE",
      rendererHints: { rowBits: 32 },
      meta: { rfc: 791, section: "3.1", aliases: ["ip"] },
      abbrev: "ip",
      defs: {
        ipv4Addr: {
          id: "ipv4Addr",
          fields: [
            { id: "oct0", name: "O0", type: { kind: "int", bits: 8 } },
            { id: "oct1", name: "O1", type: { kind: "int", bits: 8 } },
          ],
        },
      },
      body: [
        {
          id: "version",
          name: "Version",
          type: { kind: "int", bits: 4 },
          const: 4,
          category: "identifier",
        },
        {
          id: "ihl",
          name: "IHL",
          type: { kind: "int", bits: 4 },
          category: "length",
        },
        { kind: "ref", ref: "ipv4Addr", id: "src", name: "Source" },
        {
          kind: "switch",
          id: "payload",
          on: { kind: "ref", field: "ihl" },
          cases: {
            "6": {
              id: "tcp",
              fields: [
                { id: "sp", name: "SP", type: { kind: "int", bits: 16 } },
              ],
            },
            "0-9": { id: "low", fields: [] },
            _: { id: "unk", fields: [] },
          },
        },
      ],
      constraints: [
        { lhs: { kind: "ref", field: "ihl" }, rhs: { kind: "lit", value: 5 } },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects a packet missing required name", () => {
    expect(validate({ body: [] })).toBe(false);
  });

  it("accepts the new container kinds (bounded, align, virtual)", () => {
    const pkt = {
      name: "t",
      body: [
        { kind: "virtual", id: "v", expr: { kind: "lit", value: 1 } },
        { kind: "align", to: 32 },
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 8 },
          fields: [
            {
              id: "x",
              name: "X",
              type: { kind: "bytes", n: { kind: "remaining" } },
            },
          ],
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("accepts meta.rfc in the multi-layer { defined, updates } form (RfcRef, §5.4)", () => {
    const pkt = {
      name: "t",
      meta: { rfc: { defined: 791, updates: [2474, 3168] }, section: "1.4" },
      body: [
        {
          id: "dscp",
          name: "DSCP",
          type: { kind: "int", bits: 6 },
          meta: { rfc: { defined: 2474, updates: [3260, 8622] }, section: "3" },
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("still accepts a bare numeric meta.rfc (RfcRef back-compat)", () => {
    expect(validate({ name: "t", meta: { rfc: 791 }, body: [] })).toBe(true);
  });

  it("rejects a meta.rfc object missing the required `defined`", () => {
    expect(
      validate({ name: "t", meta: { rfc: { updates: [2474] } }, body: [] }),
    ).toBe(false);
  });

  it("accepts free-form classification tags/family on packet meta (§1.1)", () => {
    expect(
      validate({
        name: "t",
        meta: { rfc: 4271, family: "bgp", tags: ["routing", "tcp-based"] },
        body: [],
      }),
    ).toBe(true);
    // shape is enforced: tags is string[], family is string
    expect(validate({ name: "t", meta: { tags: "routing" }, body: [] })).toBe(
      false,
    );
    expect(validate({ name: "t", meta: { family: ["bgp"] }, body: [] })).toBe(
      false,
    );
  });

  it("fixes the RfcRef acceptance boundary (§5.4)", () => {
    // Empty updates list is accepted (no minItems).
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [] } },
        body: [],
      }),
    ).toBe(true);
    // updates entries must be integers.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [1.5] } },
        body: [],
      }),
    ).toBe(false);
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: ["x"] } },
        body: [],
      }),
    ).toBe(false);
    // Unknown provenance keys are rejected (additionalProperties: false).
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, obsoletes: [760] } },
        body: [],
      }),
    ).toBe(false);
    // defined must be an integer, not a numeric string.
    expect(
      validate({ name: "t", meta: { rfc: { defined: "791" } }, body: [] }),
    ).toBe(false);
  });

  it("accepts object-form updates entries with an optional section (§5.4, D8)", () => {
    // Object-form { rfc, section? } entry.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ rfc: 2474, section: "3" }] } },
        body: [],
      }),
    ).toBe(true);
    // Bare + object mix.
    expect(
      validate({
        name: "t",
        meta: {
          rfc: { defined: 791, updates: [2474, { rfc: 3168, section: "5" }] },
        },
        body: [],
      }),
    ).toBe(true);
    // section is optional in the object form.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ rfc: 2474 }] } },
        body: [],
      }),
    ).toBe(true);
  });

  it("rejects malformed object-form updates entries (§5.4, D8)", () => {
    // Object form missing the required `rfc`.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ section: "3" }] } },
        body: [],
      }),
    ).toBe(false);
    // Surplus key in the object form.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ rfc: 2474, foo: 1 }] } },
        body: [],
      }),
    ).toBe(false);
    // rfc must be an integer.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ rfc: "2474" }] } },
        body: [],
      }),
    ).toBe(false);
    // section must be a string.
    expect(
      validate({
        name: "t",
        meta: { rfc: { defined: 791, updates: [{ rfc: 2474, section: 3 }] } },
        body: [],
      }),
    ).toBe(false);
  });

  it("accepts meta on bounded and encrypted regions (§5.4)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "b",
          bytes: { kind: "lit", value: 4 },
          meta: { rfc: 9000 },
          fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }],
        },
        {
          kind: "encrypted",
          id: "e",
          meta: { rfc: { defined: 9001 } },
          plaintext: {
            id: "pt",
            fields: [{ id: "y", name: "Y", type: { kind: "int", bits: 8 } }],
          },
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("accepts a field with a values dictionary (ValueEntry, §5.3)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "dscp",
          name: "DSCP",
          type: { kind: "int", bits: 6 },
          values: [
            {
              value: 46,
              name: "EF",
              label: "Expedited Forwarding",
              level: "must",
              meta: { rfc: 3246 },
            },
            { range: [8, 8], name: "CS1", meta: { rfc: { defined: 2474 } } },
          ],
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects a ValueEntry setting both value and range (oneOf)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ value: 1, range: [2, 3] }],
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("rejects a non-integer ValueEntry value (type: integer)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ value: 4.6 }],
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("rejects a ValueEntry range with the wrong arity (minItems/maxItems: 2)", () => {
    const entry = (range: number[]): unknown => ({
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ range }],
        },
      ],
    });
    expect(validate(entry([8]))).toBe(false);
    expect(validate(entry([1, 2, 8]))).toBe(false);
    expect(validate(entry([1, 8]))).toBe(true);
  });

  it("rejects non-string ValueEntry name/label/doc (type: string)", () => {
    const entry = (extra: Record<string, unknown>): unknown => ({
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 16 },
          values: [{ value: 404, ...extra }],
        },
      ],
    });
    expect(validate(entry({ name: 404 }))).toBe(false);
    expect(validate(entry({ label: 0 }))).toBe(false);
    expect(validate(entry({ doc: ["x"] }))).toBe(false);
  });

  it("rejects an invalid ValueEntry level", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ value: 1, level: "required" }],
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("accepts a ValueEntry pattern bit-predicate entry (§5.3)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "dscp",
          name: "DSCP",
          type: { kind: "int", bits: 6 },
          values: [{ pattern: "xxxx11", name: "EXP" }],
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects a ValueEntry pattern with illegal characters", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ pattern: "xx12" }],
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("rejects a ValueEntry mixing value and pattern (oneOf)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "f",
          name: "F",
          type: { kind: "int", bits: 8 },
          values: [{ value: 1, pattern: "xx11" }],
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("accepts an enum variant object carrying level and meta (§3)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "p",
          name: "P",
          type: {
            kind: "enum",
            bits: 8,
            variants: {
              "6": { label: "TCP", level: "may", meta: { rfc: 793 } },
            },
          },
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("rejects a non-decimal enum variant key (propertyNames, §3)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "p",
          name: "P",
          type: {
            kind: "enum",
            bits: 8,
            variants: { "0x6": { label: "TCP" } },
          },
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("rejects a non-string enum variant doc (type: string)", () => {
    const pkt = {
      name: "t",
      body: [
        {
          id: "p",
          name: "P",
          type: {
            kind: "enum",
            bits: 8,
            variants: { "6": { label: "TCP", doc: 793 } },
          },
        },
      ],
    };
    expect(validate(pkt)).toBe(false);
  });

  it("accepts meta on a defs struct and validates its shape (NamedStruct, §5.4/§6)", () => {
    const defsPkt = (meta: unknown): unknown => ({
      name: "t",
      defs: {
        foo: {
          id: "foo",
          meta,
          fields: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
        },
      },
      body: [{ kind: "ref", ref: "foo", id: "x", name: "X" }],
    });
    expect(
      validate(
        defsPkt({ rfc: { defined: 791, updates: [2474] }, section: "3.1" }),
      ),
    ).toBe(true);
    expect(validate(defsPkt({ rfc: 791 }))).toBe(true);
    expect(validate(defsPkt({ bogus: 1 }))).toBe(false);
  });

  it("accepts a constraint with level: should and rejects an invalid level (§9.1)", () => {
    const base = {
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
    };
    expect(
      validate({
        ...base,
        constraints: [
          {
            lhs: { kind: "ref", field: "a" },
            rhs: { kind: "lit", value: 1 },
            level: "should",
          },
        ],
      }),
    ).toBe(true);
    expect(
      validate({
        ...base,
        constraints: [
          {
            lhs: { kind: "ref", field: "a" },
            rhs: { kind: "lit", value: 1 },
            level: "x",
          },
        ],
      }),
    ).toBe(false);
  });

  it("rejects an unknown constraint key, e.g. a typo'd 'leval' (additionalProperties: false)", () => {
    expect(
      validate({
        name: "t",
        body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
        constraints: [
          {
            lhs: { kind: "ref", field: "a" },
            rhs: { kind: "lit", value: 1 },
            leval: "should",
          },
        ],
      }),
    ).toBe(false);
  });

  // C24/§8/§11.1: checksumParams may only refine a CRC parameter model.
  const cksumPkt = (algorithm: string, withParams: boolean) => ({
    name: "t",
    body: [
      {
        id: "fcs",
        name: "FCS",
        type: { kind: "int", bits: 32 },
        category: "checksum",
        checksumAlgorithm: algorithm,
        ...(withParams ? { checksumParams: { polynomial: 0x04c11db7 } } : {}),
      },
    ],
  });
  it("rejects checksumParams paired with a non-CRC algorithm (internet, adler32)", () => {
    expect(validate(cksumPkt("internet", true))).toBe(false);
    expect(validate(cksumPkt("adler32", true))).toBe(false);
  });
  it("accepts checksumParams with a CRC / custom algorithm, and non-CRC algorithms without params", () => {
    expect(validate(cksumPkt("crc32", true))).toBe(true);
    expect(validate(cksumPkt("crc32-custom", true))).toBe(true);
    expect(validate(cksumPkt("internet", false))).toBe(true);
  });
  it("accepts hex-string checksum params and a width (§8, D9)", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "crc",
            name: "CRC-64",
            type: { kind: "int", bits: 64 },
            category: "checksum",
            checksumAlgorithm: "crc64-ecma182",
            checksumParams: {
              polynomial: "0xAD93D23594C935A9",
              initValue: "0xFFFFFFFFFFFFFFFF",
              finalXOR: "0xFFFFFFFFFFFFFFFF",
              width: 64,
            },
          },
        ],
      }),
    ).toBe(true);
  });
  it("rejects a non-hex-pattern checksum param string and an out-of-range width (§8, D9)", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "crc",
            name: "CRC",
            type: { kind: "int", bits: 32 },
            category: "checksum",
            checksumParams: { polynomial: "0xZZ" },
          },
        ],
      }),
    ).toBe(false);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "crc",
            name: "CRC",
            type: { kind: "int", bits: 32 },
            category: "checksum",
            checksumParams: { polynomial: 1, width: 65 },
          },
        ],
      }),
    ).toBe(false);
  });

  // C12/§5.1: CategoryToken is a closed enum; an `align` container has no
  // `category` property at all (additionalProperties: false).
  it("rejects an unknown category token (closed CategoryToken enum, §5.1)", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "f",
            name: "F",
            type: { kind: "int", bits: 8 },
            category: "padding",
          },
        ],
      }),
    ).toBe(false);
  });
  it("rejects an align container carrying a category (align has no category property)", () => {
    expect(
      validate({
        name: "t",
        body: [{ kind: "align", to: 32, category: "reserved" }],
      }),
    ).toBe(false);
  });
});

describe("JSON Schema — bytes delimiter form (§3, D3)", () => {
  it("accepts the delimiter form", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "rl",
            name: "RL",
            type: { kind: "bytes", n: { delimiter: [13, 10] } },
          },
        ],
      }),
    ).toBe(true);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "fn",
            name: "FN",
            type: { kind: "bytes", n: { delimiter: [0] } },
          },
        ],
      }),
    ).toBe(true);
  });
  it("still accepts the plain Expr length form", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "d",
            name: "D",
            type: { kind: "bytes", n: { kind: "lit", value: 4 } },
          },
        ],
      }),
    ).toBe(true);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "d",
            name: "D",
            type: { kind: "bytes", n: { kind: "remaining" } },
          },
        ],
      }),
    ).toBe(true);
  });
  it("rejects an empty delimiter, an out-of-range byte, and an unknown key on the delimiter form", () => {
    expect(
      validate({
        name: "t",
        body: [
          { id: "x", name: "X", type: { kind: "bytes", n: { delimiter: [] } } },
        ],
      }),
    ).toBe(false);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "x",
            name: "X",
            type: { kind: "bytes", n: { delimiter: [256] } },
          },
        ],
      }),
    ).toBe(false);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "x",
            name: "X",
            type: { kind: "bytes", n: { delimiter: [0], consume: true } },
          },
        ],
      }),
    ).toBe(false);
  });
});

describe("JSON Schema — subfields (§12, D4)", () => {
  it("accepts subfields with integer and hex-string masks", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "fcf",
            name: "Frame Control",
            type: { kind: "int", bits: 16 },
            subfields: [
              {
                id: "frameType",
                name: "Frame Type",
                mask: 7,
                category: "type",
                values: [{ value: 1, label: "Data" }],
              },
              { id: "srcAddrMode", name: "Src Addr Mode", mask: "0xC000" },
            ],
          },
        ],
      }),
    ).toBe(true);
  });
  it("rejects a subfield missing id/name/mask or with a surplus key", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "f",
            name: "F",
            type: { kind: "int", bits: 8 },
            subfields: [{ id: "a", name: "A" }],
          },
        ],
      }),
    ).toBe(false);
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "f",
            name: "F",
            type: { kind: "int", bits: 8 },
            subfields: [{ id: "a", name: "A", mask: 1, bogus: 1 }],
          },
        ],
      }),
    ).toBe(false);
  });
  it("rejects a non-0x mask string", () => {
    expect(
      validate({
        name: "t",
        body: [
          {
            id: "f",
            name: "F",
            type: { kind: "int", bits: 8 },
            subfields: [{ id: "a", name: "A", mask: "ff" }],
          },
        ],
      }),
    ).toBe(false);
  });
});
