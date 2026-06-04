import { describe, expect, it } from "vitest";
import { normalize, selectArm } from "../src/normalize.js";
import type { Packet, Struct } from "../src/types.js";

describe("normalize — basic fields", () => {
  it("flattens fields with absolute bit offsets", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 4 } },
        { id: "b", name: "B", type: { kind: "int", bits: 12 } },
      ],
    };
    const n = normalize(pkt);
    expect(n.totalBits).toBe(16);
    expect(n.fields.map((f) => [f.id, f.absoluteBitOffset, f.bits])).toEqual([
      ["a", 0, 4],
      ["b", 4, 12],
    ]);
  });

  it("seeds const/defaultValue and resolves bytes length from a ref", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "len", name: "Len", type: { kind: "int", bits: 8 }, defaultValue: 3 },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "ref", field: "len" } } },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields[1]!.bits).toBe(24); // 3 bytes
  });
});

describe("normalize — ref expansion", () => {
  const ipv4Addr: Struct = {
    id: "ipv4Addr",
    fields: [
      { id: "oct0", name: "O0", type: { kind: "int", bits: 8 } },
      { id: "oct1", name: "O1", type: { kind: "int", bits: 8 } },
    ],
  };
  it("prefixes expanded ids with the ref instantiation id", () => {
    const pkt: Packet = {
      name: "t",
      defs: { ipv4Addr },
      body: [{ kind: "ref", ref: "ipv4Addr", id: "src", name: "Src" }],
    };
    const n = normalize(pkt);
    expect(n.fields.map((f) => f.id)).toEqual(["src.oct0", "src.oct1"]);
  });

  it("ref inside a repeat carries both prefix and index suffix", () => {
    const pkt: Packet = {
      name: "t",
      defs: { ipv4Addr },
      body: [
        {
          kind: "repeat",
          id: "addrs",
          count: { kind: "lit", value: 2 },
          element: { id: "el", fields: [{ kind: "ref", ref: "ipv4Addr", id: "a", name: "A" }] },
        },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.map((f) => f.id)).toEqual([
      "a.oct0#0", "a.oct1#0", "a.oct0#1", "a.oct1#1",
    ]);
  });
});

describe("selectArm — switch key matching", () => {
  const arm = (id: string): Struct => ({ id, fields: [] });
  const cases = { "6": arm("tcp"), "17,136": arm("udp"), "0-9": arm("low"), _: arm("def") };
  it("matches exact before list before range", () => {
    expect(selectArm(cases, 6)?.struct.id).toBe("tcp");
    expect(selectArm(cases, 136)?.struct.id).toBe("udp");
    expect(selectArm(cases, 3)?.struct.id).toBe("low");
  });
  it("falls back to _ default", () => {
    expect(selectArm(cases, 999)?.struct.id).toBe("def");
  });
  it("returns undefined when no case and no default", () => {
    expect(selectArm({ "1": arm("x") }, 2)).toBeUndefined();
  });
});

describe("normalize — switch range/list selection", () => {
  it("selects a range-keyed arm and parses its fields", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "proto", name: "P", type: { kind: "int", bits: 8 }, defaultValue: 5 },
        {
          kind: "switch",
          id: "sw",
          on: { kind: "ref", field: "proto" },
          cases: {
            "0-9": { id: "low", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 16 } }] },
          },
        },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.some((f) => f.id === "x")).toBe(true);
    expect(n.totalBits).toBe(8 + 16);
  });
});

describe("normalize — bounded scope + remaining", () => {
  it("remaining yields the scope's leftover bytes", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 10 },
          fields: [
            { id: "head", name: "H", type: { kind: "int", bits: 16 } }, // 2 bytes
            { id: "rest", name: "R", type: { kind: "bytes", n: { kind: "remaining" } } },
          ],
        },
      ],
    };
    const n = normalize(pkt);
    const rest = n.fields.find((f) => f.id === "rest")!;
    expect(rest.bits).toBe((10 - 2) * 8);
  });
});

describe("normalize — nested optional short-circuit", () => {
  it("skips inner optional when outer is absent", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "outer", name: "O", type: { kind: "int", bits: 8 }, defaultValue: 0 },
        {
          kind: "optional",
          when: { kind: "ref", field: "outer" },
          container: {
            kind: "optional",
            when: { kind: "lit", value: 1 },
            container: { id: "deep", name: "D", type: { kind: "int", bits: 8 } },
          },
        },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.some((f) => f.id === "deep")).toBe(false);
  });
});
