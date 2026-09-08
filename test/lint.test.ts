import { describe, expect, it } from "vitest";
import { lintPacket } from "../src/lint.js";
import { validatePacket } from "../src/validate.js";
import type { Packet, Struct } from "../src/types.js";

/** Rules fired, in order. */
const rules = (p: Packet): string[] => lintPacket(p).map((w) => w.rule);

const clean: Packet = {
  name: "t",
  version: "0.5",
  rowBits: 32,
  body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
};

describe("lintPacket — §11.4", () => {
  it("says nothing about a clean packet", () => {
    expect(lintPacket(clean)).toEqual([]);
  });

  it("never turns a warning into a validation error", () => {
    // The whole point of the separate channel: a document that trips every rule
    // is still valid PSDL. If these ever start overlapping, one of them is wrong.
    const noisy: Packet = {
      name: "t",
      rowBits: 32,
      byteOrder: "LE",
      body: [
        { id: "b0", name: "B0", type: { kind: "bits", n: 4 } },
        { id: "b1", name: "B1", type: { kind: "bits", n: 4 } },
      ],
    };
    expect(rules(noisy).length).toBeGreaterThan(0);
    expect(validatePacket(noisy)).toEqual([]);
  });

  it("1. warns when version is absent", () => {
    const { version, ...noVersion } = clean;
    void version;
    expect(rules(noVersion as Packet)).toContain("version-undeclared");
    expect(rules(clean)).not.toContain("version-undeclared");
  });

  it("2. warns when a constraint reaches into a recursive def expansion", () => {
    // `node` refs itself, so its expansion is capped and any constraint naming a
    // field inside it is silently skipped by the solver.
    const node: Struct = {
      id: "node",
      fields: [
        { id: "len", name: "Len", type: { kind: "int", bits: 8 } },
        { kind: "ref", ref: "node", id: "next", name: "Next" },
      ],
    };
    const pkt: Packet = {
      name: "t",
      version: "0.5",
      rowBits: 32,
      defs: { node },
      body: [{ kind: "ref", ref: "node", id: "root", name: "Root" }],
      constraints: [
        {
          lhs: { kind: "ref", field: "root.len" },
          rhs: { kind: "lit", value: 4 },
        },
      ],
    };
    expect(rules(pkt)).toContain("constraint-in-recursive-def");
  });

  it("2. stays quiet for a non-recursive def", () => {
    const addr: Struct = {
      id: "addr",
      fields: [{ id: "oct0", name: "O0", type: { kind: "int", bits: 8 } }],
    };
    const pkt: Packet = {
      name: "t",
      version: "0.5",
      rowBits: 32,
      defs: { addr },
      body: [{ kind: "ref", ref: "addr", id: "src", name: "Src" }],
      constraints: [
        { lhs: { kind: "ref", field: "src.oct0" }, rhs: { kind: "lit", value: 4 } },
      ],
    };
    expect(rules(pkt)).not.toContain("constraint-in-recursive-def");
  });

  it("3. warns when checksumParams overrides a well-known named CRC", () => {
    const withCrc = (algorithm: string): Packet => ({
      name: "t",
      version: "0.5",
      rowBits: 32,
      body: [
        {
          id: "ck",
          name: "Ck",
          category: "checksum",
          type: { kind: "int", bits: 32 },
          checksumAlgorithm: algorithm,
          checksumParams: { polynomial: "0x04C11DB7" },
        },
      ],
    });
    expect(rules(withCrc("crc32"))).toContain("checksum-params-override-named-crc");
    // A custom name is exactly what the advisory suggests, so it must be quiet.
    expect(rules(withCrc("myCrc"))).not.toContain("checksum-params-override-named-crc");
  });

  it("4. warns on a zero mask and on overlapping masks", () => {
    const withSubfields = (masks: number[]): Packet => ({
      name: "t",
      version: "0.5",
      rowBits: 32,
      body: [
        {
          id: "flags",
          name: "Flags",
          type: { kind: "int", bits: 8 },
          subfields: masks.map((m, i) => ({ id: `s${i}`, name: `S${i}`, mask: m })),
        },
      ],
    });
    expect(rules(withSubfields([0x0f, 0xf0]))).not.toContain("subfield-mask");
    expect(rules(withSubfields([0x0f, 0x00]))).toContain("subfield-mask");
    expect(rules(withSubfields([0x0f, 0x3c]))).toContain("subfield-mask");
  });

  it("5. warns on a multi-field bits run under byteOrder LE", () => {
    const run = (byteOrder: "BE" | "LE", n: number): Packet => ({
      name: "t",
      version: "0.5",
      rowBits: 32,
      byteOrder,
      body: Array.from({ length: n }, (_, i) => ({
        id: `b${i}`,
        name: `B${i}`,
        type: { kind: "bits" as const, n: 4 },
      })),
    });
    expect(rules(run("LE", 2))).toContain("le-bits-group");
    // One field is not a "group"; BE packs MSB-first anyway.
    expect(rules(run("LE", 1))).not.toContain("le-bits-group");
    expect(rules(run("BE", 2))).not.toContain("le-bits-group");
  });
});
