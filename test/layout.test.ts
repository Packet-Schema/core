import { describe, expect, it } from "vitest";
import { resolveLayout } from "../src/layout.js";
import type { Packet } from "../src/types.js";

describe("resolveLayout — row wrapping", () => {
  it("splits a field that straddles a row boundary into two segments", () => {
    // rowBits 32: 'a' is 24 bits (row 0, cols 0..23), 'b' is 16 bits and
    // straddles: 8 bits in row 0 (cols 24..31) and 8 bits in row 1 (cols 0..7).
    const pkt: Packet = {
      name: "t",
      rowBits: 32,
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 24 } },
        { id: "b", name: "B", type: { kind: "int", bits: 16 } },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const bCells = cells.filter((c) => c.field.id === "b");
    expect(bCells).toHaveLength(2);

    const [first, second] = bCells;
    expect(first).toMatchObject({
      row: 0,
      startBit: 24,
      endBit: 31,
      segmentIndex: 0,
      totalSegments: 2,
      isFirst: true,
      isLast: false,
      fieldStartOffset: 0,
    });
    expect(second).toMatchObject({
      row: 1,
      startBit: 0,
      endBit: 7,
      segmentIndex: 1,
      totalSegments: 2,
      isFirst: false,
      isLast: true,
      fieldStartOffset: 8,
    });
  });
});

describe("resolveLayout — group collapse with subCells", () => {
  it("collapses a group of two nibbles into one LayoutField with subCells", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 32,
      body: [
        {
          kind: "group",
          id: "g",
          name: "G",
          children: [
            { id: "child0", name: "C0", type: { kind: "bits", n: 4 } },
            { id: "child1", name: "C1", type: { kind: "bits", n: 4 } },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const gCells = cells.filter((c) => c.field.id === "g");
    expect(gCells).toHaveLength(1);
    const cell = gCells[0]!;
    expect(cell.field.bits).toBe(8);
    expect(cell.field.subfields?.map((s) => s.bits)).toEqual([4, 4]);
    expect(cell.subCells?.map((s) => s.id)).toEqual(["g:child0", "g:child1"]);
  });
});

describe("resolveLayout — rowBits validation", () => {
  it("throws when rowBits is 0", () => {
    const pkt: Packet = { name: "t", rowBits: 0, body: [] };
    expect(() => resolveLayout(pkt)).toThrow(
      /rowBits must be a positive integer/,
    );
  });

  it("falls back to 32 when rowBits is absent", () => {
    // §13 / schemas/psdl-0.5.yaml: a packet without `rowBits` is a valid PSDL
    // document and renderers fall back to 32. A 40-bit field must therefore
    // wrap at 32 bits into two segments, exactly as `rowBits: 32` would.
    const pkt: Packet = {
      name: "t",
      body: [{ id: "a", name: "A", type: { kind: "int", bits: 40 } }],
    };
    const { cells } = resolveLayout(pkt);
    expect(cells).toHaveLength(2);
    expect(cells[0]).toMatchObject({ row: 0, startBit: 0, endBit: 31 });
    expect(cells[1]).toMatchObject({ row: 1, startBit: 0, endBit: 7 });
  });
});

describe("resolveLayout — value dictionary reaches LayoutField (§5.3)", () => {
  it("carries field.values/meta onto the flat LayoutField", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 32,
      body: [
        {
          id: "proto",
          name: "Protocol",
          type: { kind: "int", bits: 8 },
          meta: { rfc: 790 },
          values: [
            { value: 6, name: "TCP" },
            { value: 17, name: "UDP" },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const f = cells.find((c) => c.field.id === "proto")!.field;
    expect(f.values).toEqual([
      { value: 6, name: "TCP" },
      { value: 17, name: "UDP" },
    ]);
    expect(f.meta).toEqual({ rfc: 790 });
  });

  it("carries the encrypted region's meta onto the wire-view blob LayoutField (§5.4)", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 32,
      body: [
        {
          kind: "encrypted",
          id: "payload",
          meta: { rfc: { defined: 9001, updates: [9999] }, section: "4" },
          plaintext: {
            id: "pt",
            fields: [
              { id: "inE", name: "InE", type: { kind: "int", bits: 24 } },
            ],
          },
        },
      ],
    };
    const { cells } = resolveLayout(pkt, { viewMode: "wire" });
    const f = cells.find((c) => c.field.id === "payload")!.field;
    expect(f.meta).toEqual({
      rfc: { defined: 9001, updates: [9999] },
      section: "4",
    });
  });
});

describe("resolveLayout — group RFC provenance reaches the parent LayoutField (§5.4)", () => {
  it("surfaces Group.meta on the collapsed parent field", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "tos",
          name: "DiffServ",
          meta: {
            rfc: { defined: 791, updates: [2474, 3168] },
            section: "1.4",
          },
          children: [
            { id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 } },
            { id: "ecn", name: "ECN", type: { kind: "int", bits: 2 } },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const parent = cells.find((c) => c.field.id === "tos")!.field;
    expect(parent.subfields?.map((s) => s.id)).toEqual(["dscp", "ecn"]);
    expect(parent.meta).toEqual({
      rfc: { defined: 791, updates: [2474, 3168] },
      section: "1.4",
    });
  });

  it("surfaces group meta on a single-child group (flat branch fallback)", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "solo",
          name: "Solo",
          meta: { rfc: 999 },
          children: [
            { id: "only", name: "Only", type: { kind: "int", bits: 8 } },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    expect(cells.find((c) => c.field.id === "only")!.field.meta).toEqual({
      rfc: 999,
    });
  });

  it("prefers field meta over group meta when both are present", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "g",
          name: "G",
          meta: { rfc: 100 },
          children: [
            {
              id: "f",
              name: "F",
              type: { kind: "int", bits: 8 },
              meta: { rfc: 200 },
            },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    expect(cells.find((c) => c.field.id === "f")!.field.meta).toEqual({
      rfc: 200,
    });
  });

  it("a virtual between two group fields does not split the collapse (§5.4)", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "g2",
          name: "G2",
          meta: { rfc: 888 },
          children: [
            {
              id: "ga",
              name: "GA",
              type: { kind: "int", bits: 4 },
              meta: { rfc: 100 },
            },
            { kind: "virtual", id: "v1", expr: { kind: "ref", field: "ga" } },
            { id: "gb", name: "GB", type: { kind: "int", bits: 4 } },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    // The group still collapses into one parent LayoutField with its meta…
    const parent = cells.find((c) => c.field.id === "g2")!.field;
    expect(parent.name).toBe("G2");
    expect(parent.bits).toBe(8);
    expect(parent.meta).toEqual({ rfc: 888 });
    // …and the zero-width virtual does not appear as a subfield.
    expect(parent.subfields?.map((s) => s.id)).toEqual(["ga", "gb"]);
    expect(parent.subfields![0]!.meta).toEqual({ rfc: 100 });
  });

  it("a group whose only sized member sits next to a virtual still gets the flat groupMeta fallback", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "solo",
          name: "Solo",
          meta: { rfc: 999 },
          children: [
            { kind: "virtual", id: "v", expr: { kind: "lit", value: 1 } },
            { id: "only", name: "Only", type: { kind: "int", bits: 8 } },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    // One real member → flat (a virtual never forces a collapsed parent),
    // and the flat branch still surfaces the group's provenance.
    expect(cells.find((c) => c.field.id === "only")!.field.meta).toEqual({
      rfc: 999,
    });
  });
});

describe("resolveLayout — subfield values/meta on a collapsed group (§5.3/§5.4)", () => {
  it("copies each child's values and meta onto its LayoutSubField (ToS DSCP+ECN)", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "group",
          id: "tos",
          name: "DiffServ",
          children: [
            {
              id: "dscp",
              name: "DSCP",
              type: { kind: "int", bits: 6 },
              meta: { rfc: 2474 },
              values: [{ value: 46, name: "EF" }],
            },
            {
              id: "ecn",
              name: "ECN",
              type: { kind: "int", bits: 2 },
              meta: { rfc: 3168 },
              values: [{ value: 3, name: "CE" }],
            },
          ],
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const parent = cells.find((c) => c.field.id === "tos")!.field;
    expect(parent.subfields).toHaveLength(2);
    expect(parent.subfields![0]).toEqual({
      id: "dscp",
      name: "DSCP",
      bits: 6,
      values: [{ value: 46, name: "EF" }],
      meta: { rfc: 2474 },
    });
    expect(parent.subfields![1]).toEqual({
      id: "ecn",
      name: "ECN",
      bits: 2,
      values: [{ value: 3, name: "CE" }],
      meta: { rfc: 3168 },
    });
    // Reachable through the subCells too.
    const subCells = cells.find((c) => c.field.id === "tos")!.subCells!;
    expect(subCells.map((s) => s.subfield.values?.[0]?.name)).toEqual([
      "EF",
      "CE",
    ]);
  });
});

describe("resolveLayout — subfield id stripping under nested repeats", () => {
  const groupOf = (children: Packet["body"]): Packet["body"][number] => ({
    kind: "group",
    id: "g",
    name: "G",
    children,
  });
  const nibbles: Packet["body"] = [
    { id: "a", name: "A", type: { kind: "bits", n: 4 } },
    { id: "b", name: "B", type: { kind: "bits", n: 4 } },
  ];

  it("strips a single-level repeat suffix (#N) back to the source field id", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 1 },
          element: { id: "el", fields: [groupOf(nibbles)] },
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const parent = cells.find((c) => c.field.id === "g#0")!.field;
    expect(parent.subfields?.map((s) => s.id)).toEqual(["a", "b"]);
  });

  it("strips a nested-repeat suffix (#N_M) the same way", () => {
    const pkt: Packet = {
      name: "t",
      rowBits: 8,
      body: [
        {
          kind: "repeat",
          id: "outer",
          count: { kind: "lit", value: 1 },
          element: {
            id: "oel",
            fields: [
              {
                kind: "repeat",
                id: "inner",
                count: { kind: "lit", value: 2 },
                element: { id: "iel", fields: [groupOf(nibbles)] },
              },
            ],
          },
        },
      ],
    };
    const { cells } = resolveLayout(pkt);
    const parents = cells.filter((c) => c.field.subfields !== undefined);
    expect(parents.map((c) => c.field.id)).toEqual(["g#0_0", "g#0_1"]);
    for (const c of parents) {
      expect(c.field.subfields!.map((s) => s.id)).toEqual(["a", "b"]);
      expect(c.subCells!.map((s) => s.id)).toEqual([
        `${c.field.id}:a`,
        `${c.field.id}:b`,
      ]);
    }
  });
});
