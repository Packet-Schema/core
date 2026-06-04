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
    expect(() => resolveLayout(pkt)).toThrow(/rowBits must be a positive integer/);
  });

  it("throws when rowBits is absent", () => {
    const pkt: Packet = { name: "t", body: [] };
    expect(() => resolveLayout(pkt)).toThrow(/rowBits must be a positive integer/);
  });
});
