import { describe, expect, it } from "vitest";
import { berLenEnvKey, normalize, selectArm, varintBitsEnvKey } from "../src/normalize.js";
import { peekEnvKey } from "../src/expr.js";
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

describe("normalize — encrypted", () => {
  const pkt: Packet = {
    name: "t",
    body: [
      {
        kind: "encrypted",
        id: "enc",
        plaintext: {
          id: "pt",
          fields: [
            { id: "x", name: "X", type: { kind: "int", bits: 8 } },
            { id: "y", name: "Y", type: { kind: "int", bits: 8 } },
          ],
        },
        headerProtected: ["x"],
        contextNote: "AEAD",
      },
    ],
  };

  it("wire mode collapses to a single encrypted field", () => {
    const n = normalize(pkt, new Map(), { viewMode: "wire" });
    expect(n.fields).toHaveLength(1);
    const f = n.fields[0]!;
    expect(f.id).toBe("enc");
    expect(f.bits).toBe(16);
    expect(f.encrypted).toBe(true);
    expect(f.encryptedContextNote).toBe("AEAD");
    expect(n.totalBits).toBe(16);
  });

  it("semantic mode expands children with encrypted context", () => {
    const n = normalize(pkt, new Map(), { viewMode: "semantic" });
    expect(n.fields.map((f) => f.id)).toEqual(["x", "y"]);
    const [x, y] = n.fields;
    expect(x!.encryptedParentId).toBe("enc");
    expect(x!.encryptedContextNote).toBe("AEAD");
    expect(x!.headerProtected).toBe(true);
    expect(y!.encryptedParentId).toBe("enc");
    expect(y!.encryptedContextNote).toBe("AEAD");
    expect(y!.headerProtected).toBeUndefined();
  });

  it("wire-mode bit count comes from wireBits when present", () => {
    const withWireBits: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "enc",
          wireBits: { kind: "lit", value: 40 },
          plaintext: {
            id: "pt",
            fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }],
          },
        },
      ],
    };
    const n = normalize(withWireBits, new Map(), { viewMode: "wire" });
    expect(n.fields[0]!.bits).toBe(40);
  });
});

describe("normalize — align", () => {
  it("rounds up to a whole byte then to the boundary", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 4 } },
        { kind: "align", to: 16 },
        { id: "b", name: "B", type: { kind: "int", bits: 8 } },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.map((f) => [f.id, f.absoluteBitOffset, f.bits])).toEqual([
      ["a", 0, 4],
      ["b", 16, 8],
    ]);
    expect(n.totalBits).toBe(24);
  });

  it("errors when align padding exceeds a bounded scope budget", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 2 },
          fields: [
            { id: "a", name: "A", type: { kind: "int", bits: 4 } },
            { kind: "align", to: 32 },
          ],
        },
      ],
    };
    expect(() => normalize(pkt)).toThrow(/bounded scope/);
  });
});

describe("normalize — repeat count modes", () => {
  const eosPkt: Packet = {
    name: "t",
    body: [
      {
        kind: "repeat",
        id: "r",
        count: "eos",
        element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 16 } }] },
      },
    ],
  };

  it("eos yields zero iterations without env injection", () => {
    const n = normalize(eosPkt);
    expect(n.fields).toHaveLength(0);
    expect(n.totalBits).toBe(0);
  });

  it("eos honors an injected iteration count", () => {
    const n = normalize(eosPkt, new Map([["r", 3]]));
    expect(n.fields).toHaveLength(3);
  });

  it("until form resolves via injected env id", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { until: { kind: "lit", value: 0 } },
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] },
        },
      ],
    };
    const n = normalize(pkt, new Map([["r", 2]]));
    expect(n.fields).toHaveLength(2);
  });

  it("populates env[repeat.id] with the iteration count for fixed repeats", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 2 },
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }] },
        },
        { id: "after", name: "After", type: { kind: "bytes", n: { kind: "ref", field: "r" } } },
      ],
    };
    const n = normalize(pkt);
    // bytes length = ref('r') = iteration count 2 -> 16 bits
    expect(n.fields.find((f) => f.id === "after")!.bits).toBe(16);
  });
});

describe("normalize — virtual & group", () => {
  it("binds a virtual value into env for later fields", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { kind: "virtual", id: "v", expr: { kind: "lit", value: 3 } },
        { id: "d", name: "D", type: { kind: "bytes", n: { kind: "ref", field: "v" } } },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields[0]).toMatchObject({ id: "v", bits: 0, virtual: true, absoluteBitOffset: 0 });
    expect(n.fields[1]!.bits).toBe(24);
  });

  it("tags grouped fields with groupId/groupName", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { kind: "group", id: "g", name: "G", children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }] },
      ],
    };
    const n = normalize(pkt);
    const a = n.fields.find((f) => f.id === "a")!;
    expect(a.groupId).toBe("g");
    expect(a.groupName).toBe("G");
  });

  it("suffixes groupId with the repeat index inside a repeat", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 1 },
          element: {
            id: "el",
            fields: [
              { kind: "group", id: "g", name: "G", children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }] },
            ],
          },
        },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.find((f) => f.id === "a#0")!.groupId).toBe("g#0");
  });
});

describe("normalize — recursive def expansion", () => {
  it("terminates on a recursive self-referential def", () => {
    const pkt: Packet = {
      name: "t",
      defs: {
        node: {
          id: "node",
          recursive: true,
          fields: [
            { id: "v", name: "V", type: { kind: "int", bits: 8 } },
            { kind: "ref", ref: "node", id: "child" },
          ],
        },
      },
      body: [{ kind: "ref", ref: "node", id: "root" }],
    };
    let n: ReturnType<typeof normalize> | undefined;
    expect(() => { n = normalize(pkt); }).not.toThrow();
    expect(n!.fields.length).toBeLessThanOrEqual(65);
    expect(n!.fields.length).toBeGreaterThan(0);
  });
});

describe("normalize — error guards", () => {
  it("throws when 'remaining' sizes a bytes field while mid-byte", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 8 },
          fields: [
            { id: "a", name: "A", type: { kind: "int", bits: 4 } },
            { id: "rest", name: "R", type: { kind: "bytes", n: { kind: "remaining" } } },
          ],
        },
      ],
    };
    expect(() => normalize(pkt, new Map(), { totalBits: 64 })).toThrow(/mid-byte/);
  });

  it("selectArm throws on a reversed range key", () => {
    expect(() => selectArm({ "9-1": { id: "x", fields: [] } }, 5)).toThrow(/reversed range/);
  });

  it("throws when a bounded scope is over-consumed", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 2 },
          fields: [{ id: "big", name: "Big", type: { kind: "int", bits: 32 } }],
        },
      ],
    };
    expect(() => normalize(pkt)).toThrow(/over-consumed/);
  });
});

describe("normalize — prevIter (§10.4) end-to-end", () => {
  it("each iteration's bytes field is sized by the previous iteration's value", () => {
    // element: len (int8, default 1) then pad (bytes n = prevIter('len')).
    // Inject per-iteration len values via the qualified emitted ids so that
    // iteration i>0 reads iteration i-1's len. Iteration 0 uses the seeded
    // default (1 byte).
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 3 },
          element: {
            id: "el",
            fields: [
              { id: "len", name: "Len", type: { kind: "int", bits: 8 }, defaultValue: 1 },
              { id: "pad", name: "Pad", type: { kind: "bytes", n: { kind: "prevIter", field: "len" } } },
            ],
          },
        },
      ],
    };
    // len values seen per iteration: i0=2, i1=5 (after parse, env holds value).
    const env = new Map<string, number>([
      ["len#0", 2],
      ["len#1", 5],
      ["len#2", 9],
    ]);
    const n = normalize(pkt, env);
    const pads = n.fields.filter((f) => f.id.startsWith("pad#"));
    // i0 uses the seeded default (1 byte = 8 bits).
    expect(pads[0]!.bits).toBe(1 * 8);
    // i1 uses len#0 = 2 bytes.
    expect(pads[1]!.bits).toBe(2 * 8);
    // i2 uses len#1 = 5 bytes.
    expect(pads[2]!.bits).toBe(5 * 8);
  });
});

describe("normalize — prevIter for nested (grouped) element fields (§10.4, fix #3/#7)", () => {
  it("resolves prevIter for a field nested inside a group within the element", () => {
    // element wraps the discriminating field `len` inside a group, plus a
    // sibling `pad` sized by prevIter('len'). Pre-fix, collectElementFields
    // only saw top-level fields, so prevIter('len') stayed 0 every iteration.
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 3 },
          element: {
            id: "el",
            fields: [
              {
                kind: "group",
                id: "g",
                name: "G",
                children: [{ id: "len", name: "Len", type: { kind: "int", bits: 8 }, defaultValue: 1 }],
              },
              { id: "pad", name: "Pad", type: { kind: "bytes", n: { kind: "prevIter", field: "len" } } },
            ],
          },
        },
      ],
    };
    // Per-iteration len values are emitted as len#0, len#1 (group does not
    // extend the id prefix).
    const env = new Map<string, number>([
      ["len#0", 2],
      ["len#1", 5],
      ["len#2", 9],
    ]);
    const n = normalize(pkt, env);
    const pads = n.fields.filter((f) => f.id.startsWith("pad#"));
    expect(pads[0]!.bits).toBe(1 * 8); // i0: seeded default 1 byte
    expect(pads[1]!.bits).toBe(2 * 8); // i1: prevIter(len) = len#0 = 2
    expect(pads[2]!.bits).toBe(5 * 8); // i2: prevIter(len) = len#1 = 5
  });
});

describe("normalize — wireSize aggregate across repeat iterations (§4)", () => {
  it("a trailing field sees the aggregate byte footprint of the whole repeat", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: { kind: "lit", value: 2 },
          element: { id: "el", fields: [{ id: "v", name: "V", type: { kind: "int", bits: 16 } }] },
        },
        { id: "trail", name: "Trail", type: { kind: "bytes", n: { kind: "wireSize", target: "r" } } },
      ],
    };
    const n = normalize(pkt);
    // 2 iterations * 16 bits = 32 bits = 4 bytes; trail sized in bytes -> 4*8 bits.
    expect(n.fields.find((f) => f.id === "trail")!.bits).toBe(4 * 8);
  });
});

describe("typeBits — varint / berLength decoder contract", () => {
  it("varint width comes from the injected varint-bits key, default 0", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "v", name: "V", type: { kind: "varint", encoding: "leb128" } }],
    };
    const injected = normalize(pkt, new Map([[varintBitsEnvKey("v"), 24]]));
    expect(injected.fields[0]!.bits).toBe(24);
    const noInjection = normalize(pkt);
    expect(noInjection.fields[0]!.bits).toBe(0);
  });

  it("varint value slot does NOT determine wire width (§6 value/width fix)", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "v", name: "V", type: { kind: "varint", encoding: "leb128" }, defaultValue: 5 }],
    };
    // env['v'] holds the value 5; width must stay 0 (not 5 bits).
    expect(normalize(pkt).fields[0]!.bits).toBe(0);
  });

  it("berLength width comes from the injected key, default 8", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "l", name: "L", type: { kind: "berLength" } }],
    };
    const injected = normalize(pkt, new Map([[berLenEnvKey("l"), 16]]));
    expect(injected.fields[0]!.bits).toBe(16);
    const dflt = normalize(pkt);
    expect(dflt.fields[0]!.bits).toBe(8);
  });
});

describe("recordWireSize — sub-byte fields (§4)", () => {
  it("two adjacent nibbles record a full byte aggregate, not 0", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "group",
          id: "g",
          name: "G",
          children: [
            { id: "hi", name: "Hi", type: { kind: "bits", n: 4 } },
            { id: "lo", name: "Lo", type: { kind: "bits", n: 4 } },
          ],
        },
        { id: "tail", name: "Tail", type: { kind: "bytes", n: { kind: "wireSize", target: "g" } } },
      ],
    };
    const n = normalize(pkt);
    // group g spans 8 bits = 1 byte; tail sized by wireSize(g) -> 1*8 bits.
    // Pre-fix, each 4-bit nibble floored to 0 bytes, so wireSize(g) was 0.
    expect(n.fields.find((f) => f.id === "tail")!.bits).toBe(1 * 8);
  });
});

describe("normalize — align top-level cap vs unbounded (§5/§1104, coverage #14)", () => {
  it("caps padding at the injected total instead of throwing", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 4 } },
        { kind: "align", to: 32 },
      ],
    };
    // Top-level budget (8 bits) is smaller than the 32-bit align target: the
    // align caps to the 4 remaining bits (offset 4 -> 8), it does NOT throw.
    let n!: ReturnType<typeof normalize>;
    expect(() => { n = normalize(pkt, new Map(), { totalBits: 8 }); }).not.toThrow();
    expect(n.totalBits).toBe(8);
  });

  it("aligns fully to the boundary when no total is injected", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 4 } },
        { kind: "align", to: 32 },
      ],
    };
    // No totalBits -> no budgeted top frame -> align advances unbounded to 32.
    expect(normalize(pkt).totalBits).toBe(32);
  });
});

describe("normalize — peek decoder hand-off (§11.3, coverage #15)", () => {
  it("switch.on = peek selects the disc=0 arm with no injection, the matching arm when injected", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "switch",
          id: "sw",
          on: { kind: "peek", bits: 8 },
          cases: {
            "0": { id: "a0", fields: [{ id: "x16", name: "X16", type: { kind: "int", bits: 16 } }] },
            "5": { id: "a5", fields: [{ id: "x8", name: "X8", type: { kind: "int", bits: 8 } }] },
            _: { id: "ad", fields: [{ id: "xd", name: "Xd", type: { kind: "int", bits: 32 } }] },
          },
        },
      ],
    };
    // No peek injection -> peek = 0 -> the "0" arm.
    const none = normalize(pkt);
    expect(none.fields.map((f) => f.id)).toContain("x16");
    expect(none.totalBits).toBe(16);
    // Inject peek(0,8) = 5 -> the "5" arm.
    const five = normalize(pkt, new Map([[peekEnvKey(0, 8), 5]]));
    expect(five.fields.map((f) => f.id)).toContain("x8");
    expect(five.totalBits).toBe(8);
  });

  it("optional.when = peek is absent without injection and present when injected non-zero", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "optional",
          id: "opt",
          when: { kind: "peek", bits: 8 },
          container: { id: "p", name: "P", type: { kind: "int", bits: 8 } },
        },
      ],
    };
    expect(normalize(pkt).fields.map((f) => f.id)).not.toContain("p");
    expect(normalize(pkt, new Map([[peekEnvKey(0, 8), 1]])).fields.map((f) => f.id)).toContain("p");
  });
});

describe("normalize — recursive ref expansion cap (MAX_REF_DEPTH, coverage #16)", () => {
  it("expands a recursive def exactly 64 levels deep and terminates", () => {
    const pkt: Packet = {
      name: "t",
      defs: {
        node: {
          id: "node",
          recursive: true,
          fields: [
            { id: "v", name: "V", type: { kind: "int", bits: 8 } },
            { kind: "ref", ref: "node", id: "child" },
          ],
        },
      },
      body: [{ kind: "ref", ref: "node", id: "root" }],
    };
    let n!: ReturnType<typeof normalize>;
    expect(() => { n = normalize(pkt); }).not.toThrow();
    const vCount = n.fields.filter((f) => f.name === "V").length;
    expect(vCount).toBe(64);
  });
});

describe("normalize — bounded under-consumption advances to scope end (coverage #17)", () => {
  it("a trailing field starts at the padded boundary and wireSize records the full budget", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "b",
          bytes: { kind: "lit", value: 4 },
          fields: [{ id: "h", name: "H", type: { kind: "int", bits: 8 } }],
        },
        { id: "tail", name: "Tail", type: { kind: "int", bits: 8 } },
        // sized in bytes from the bounded scope's recorded footprint (4 bytes).
        { id: "szchk", name: "SzChk", type: { kind: "bytes", n: { kind: "wireSize", target: "b" } } },
      ],
    };
    const n = normalize(pkt);
    // children consumed 8 bits but the budget is 32 -> tail starts at 32.
    expect(n.fields.find((f) => f.id === "tail")!.absoluteBitOffset).toBe(32);
    // tail is 8 bits (32..40); totalBits then includes szchk (4 bytes = 32 bits).
    expect(n.fields.find((f) => f.id === "tail")!.bits).toBe(8);
    // bounded b recorded a 4-byte footprint despite under-filling.
    expect(n.fields.find((f) => f.id === "szchk")!.bits).toBe(4 * 8);
    expect(n.totalBits).toBe(40 + 32);
  });
});

describe("normalize — nested repeat qualified eos count (coverage #18)", () => {
  it("prefers the per-instance qualified count over the bare id", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "outer",
          count: { kind: "lit", value: 2 },
          element: {
            id: "oel",
            fields: [
              {
                kind: "repeat",
                id: "inner",
                count: "eos",
                element: { id: "iel", fields: [{ id: "w", name: "W", type: { kind: "int", bits: 8 } }] },
              },
            ],
          },
        },
      ],
    };
    // Inject distinct per-instance counts under the qualified inner ids.
    const env = new Map<string, number>([
      ["inner#0", 1],
      ["inner#1", 3],
    ]);
    const n = normalize(pkt, env);
    const ws = n.fields.filter((f) => f.name === "W");
    // outer index 0 -> 1 inner iteration; outer index 1 -> 3 inner iterations.
    const under0 = ws.filter((f) => f.id.includes("#0_"));
    const under1 = ws.filter((f) => f.id.includes("#1_"));
    expect(under0.length).toBe(1);
    expect(under1.length).toBe(3);
  });
});

describe("normalize — encrypted plaintext wireBits budget (fix #1/#2)", () => {
  it("snaps the cursor to the wireBits end so following fields are placed correctly", () => {
    // wireBits = 16 bytes (128 bits, e.g. AEAD ciphertext+tag); plaintext is a
    // single 64-bit int. After the block the next field must start at +128,
    // not +64.
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "enc",
          wireBits: { kind: "lit", value: 16 * 8 },
          plaintext: {
            id: "pt",
            fields: [{ id: "v", name: "V", type: { kind: "int", bits: 64 } }],
          },
        },
        { id: "after", name: "After", type: { kind: "int", bits: 8 } },
      ],
    };
    const n = normalize(pkt, new Map(), { viewMode: "semantic" });
    // plaintext field v occupies 0..64.
    expect(n.fields.find((f) => f.id === "v")!.absoluteBitOffset).toBe(0);
    // `after` starts at the wireBits end (128), not at 64.
    expect(n.fields.find((f) => f.id === "after")!.absoluteBitOffset).toBe(128);
    expect(n.totalBits).toBe(128 + 8);
  });

  it("over-consuming the wireBits budget is a runtime error", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "enc",
          wireBits: { kind: "lit", value: 8 },
          plaintext: {
            id: "pt",
            fields: [{ id: "v", name: "V", type: { kind: "int", bits: 32 } }],
          },
        },
      ],
    };
    expect(() => normalize(pkt, new Map(), { viewMode: "semantic" })).toThrow(/over-consumed/);
  });

  it("wireSize(encryptedId) resolves to the container footprint in both view modes (fix #2)", () => {
    const mk = (): Packet => ({
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "cipher",
          wireBits: { kind: "lit", value: 10 * 8 },
          plaintext: {
            id: "pt",
            fields: [{ id: "v", name: "V", type: { kind: "int", bits: 16 } }],
          },
        },
        { id: "len", name: "Len", type: { kind: "bytes", n: { kind: "wireSize", target: "cipher" } } },
      ],
    });
    // wire mode: encrypted collapses to a 10-byte field; wireSize(cipher)=10.
    const wire = normalize(mk(), new Map(), { viewMode: "wire" });
    expect(wire.fields.find((f) => f.id === "len")!.bits).toBe(10 * 8);
    // semantic mode: plaintext expands but the budget end is 10 bytes; the
    // recorded footprint is still the container's wire size.
    const sem = normalize(mk(), new Map(), { viewMode: "semantic" });
    expect(sem.fields.find((f) => f.id === "len")!.bits).toBe(10 * 8);
  });
});

describe("normalize — switchCase tag propagation (coverage #12, fix #3)", () => {
  it("tags both direct and group-nested arm fields with the arm key", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "disc", name: "Disc", type: { kind: "int", bits: 8 }, defaultValue: 17 },
        {
          kind: "switch",
          id: "sw",
          on: { kind: "ref", field: "disc" },
          cases: {
            "17,136": {
              id: "arm",
              fields: [
                { id: "x", name: "X", type: { kind: "int", bits: 8 } },
                {
                  kind: "group",
                  id: "g",
                  name: "G",
                  children: [{ id: "y", name: "Y", type: { kind: "int", bits: 8 } }],
                },
              ],
            },
          },
        },
      ],
    };
    const n = normalize(pkt);
    // Direct child x carries the arm key.
    expect(n.fields.find((f) => f.id === "x")!.switchCase).toBe("17,136");
    // Nested (grouped) field y now ALSO carries the arm key (fix #3 propagates
    // the case through the whole arm subtree, not just direct children).
    expect(n.fields.find((f) => f.id === "y")!.switchCase).toBe("17,136");
  });
});

describe("normalize — cross-repeat prevIter/wireSize isolation (coverage #13)", () => {
  it("a second sibling repeat does not inherit the first repeat's prevIter values", () => {
    const mkRepeat = (id: string) => ({
      kind: "repeat" as const,
      id,
      count: { kind: "lit" as const, value: 2 },
      element: {
        id: `${id}el`,
        fields: [
          { id: "len", name: "Len", type: { kind: "int" as const, bits: 8 }, defaultValue: 1 },
          { id: "pad", name: "Pad", type: { kind: "bytes" as const, n: { kind: "prevIter" as const, field: "len" } } },
        ],
      },
    });
    const pkt: Packet = { name: "t", body: [mkRepeat("r1"), mkRepeat("r2")] };
    // Inject len values only for r1's instances (qualified emitted ids).
    const env = new Map<string, number>([
      ["len#0", 7],
      ["len#1", 9],
    ]);
    const n = normalize(pkt, env);
    const pads = n.fields.filter((f) => f.id.startsWith("pad#"));
    // r1: i0 uses seeded default (1 byte), i1 uses len#0 = 7 bytes.
    expect(pads[0]!.bits).toBe(1 * 8);
    expect(pads[1]!.bits).toBe(7 * 8);
    // r2: its first pad MUST use the seeded default (1 byte), proving the
    // savedPrevIter restore wiped r1's leaked last value.
    expect(pads[2]!.bits).toBe(1 * 8);
  });

  it("wireSize of the second repeat reflects only its own footprint, not the sum", () => {
    const mkRepeat = (id: string, count: number) => ({
      kind: "repeat" as const,
      id,
      count: { kind: "lit" as const, value: count },
      element: { id: `${id}el`, fields: [{ id: "v", name: "V", type: { kind: "int" as const, bits: 8 } }] },
    });
    const pkt: Packet = {
      name: "t",
      body: [
        mkRepeat("r1", 3),
        mkRepeat("r2", 2),
        { id: "tail", name: "Tail", type: { kind: "bytes", n: { kind: "wireSize", target: "r2" } } },
      ],
    };
    const n = normalize(pkt);
    // r2 has 2 * 8 bits = 2 bytes; tail must be 2 bytes, NOT 3+2=5.
    expect(n.fields.find((f) => f.id === "tail")!.bits).toBe(2 * 8);
  });
});

describe("normalize — nested encrypted + wireBits remaining scope (coverage #14)", () => {
  it("remaining inside an encrypted.plaintext yields the wireBits leftover bytes", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "enc",
          wireBits: { kind: "lit", value: 10 * 8 },
          plaintext: {
            id: "pt",
            fields: [
              { id: "head", name: "Head", type: { kind: "int", bits: 16 } }, // 2 bytes
              { id: "rest", name: "Rest", type: { kind: "bytes", n: { kind: "remaining" } } },
            ],
          },
        },
      ],
    };
    const n = normalize(pkt, new Map(), { viewMode: "semantic" });
    // 10 - 2 = 8 bytes remaining.
    expect(n.fields.find((f) => f.id === "rest")!.bits).toBe((10 - 2) * 8);
  });

  it("nested encrypted: innermost frame owns encryptedParentId and headerProtected", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "outer",
          contextNote: "OUTER",
          plaintext: {
            id: "opt",
            fields: [
              { id: "ofield", name: "OField", type: { kind: "int", bits: 8 } },
              {
                kind: "encrypted",
                id: "inner",
                contextNote: "INNER",
                headerProtected: ["ifield"],
                plaintext: {
                  id: "ipt",
                  fields: [{ id: "ifield", name: "IField", type: { kind: "int", bits: 8 } }],
                },
              },
            ],
          },
        },
      ],
    };
    const n = normalize(pkt, new Map(), { viewMode: "semantic" });
    const ofield = n.fields.find((f) => f.id === "ofield")!;
    const ifield = n.fields.find((f) => f.id === "ifield")!;
    // outer-only field tagged to outer.
    expect(ofield.encryptedParentId).toBe("outer");
    expect(ofield.headerProtected).toBeUndefined();
    // inner field tagged to the innermost frame and headerProtected.
    expect(ifield.encryptedParentId).toBe("inner");
    expect(ifield.headerProtected).toBe(true);
  });
});

describe("normalize — top-level remaining/enclosingBits without injected total (fix #7)", () => {
  it("throws when remaining sizes a top-level bytes field with no totalBits", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "rest", name: "Rest", type: { kind: "bytes", n: { kind: "remaining" } } }],
    };
    // No totalBits injected -> top-level remaining has no defined budget (§11.2).
    expect(() => normalize(pkt)).toThrow(/did not inject the total packet size/);
    // With totalBits it resolves normally.
    expect(normalize(pkt, new Map(), { totalBits: 5 * 8 }).fields[0]!.bits).toBe(5 * 8);
  });

  it("throws when enclosingBits is used at the top-level body with no totalBits", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          id: "n",
          name: "N",
          type: {
            kind: "bytes",
            n: { kind: "op", op: "/", a: { kind: "enclosingBits" }, b: { kind: "lit", value: 8 } },
          },
        },
      ],
    };
    expect(() => normalize(pkt)).toThrow(/did not inject the total packet size/);
  });
});

describe("normalize — mid-byte remaining is bytes-sizing-specific (fix #8, coverage #15)", () => {
  it("remaining in a non-bytes slot (bounded.bytes) does NOT throw mid-byte", () => {
    // 4-bit field leaves the cursor mid-byte; the bounded uses `remaining` to
    // size its byte budget. §11.2 only forbids the bytes-FIELD-sizing case, so
    // this spec-legal use must not throw.
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "nib", name: "Nib", type: { kind: "bits", n: 4 } },
        {
          kind: "bounded",
          id: "b",
          bytes: { kind: "remaining" },
          fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }],
        },
      ],
    };
    expect(() => normalize(pkt, new Map(), { totalBits: 64 })).not.toThrow();
  });

  it("remaining sizing a bytes field mid-byte still throws (emit guard)", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 8 },
          fields: [
            { id: "a", name: "A", type: { kind: "int", bits: 4 } },
            { id: "rest", name: "R", type: { kind: "bytes", n: { kind: "remaining" } } },
          ],
        },
      ],
    };
    expect(() => normalize(pkt, new Map(), { totalBits: 64 })).toThrow(/mid-byte/);
  });
});

describe("normalize — typeBits edge cases & byteOrder propagation (coverage #17)", () => {
  it("bytes with a negative length clamps to 0 bits", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "b", name: "B", type: { kind: "bytes", n: { kind: "lit", value: -3 } } }],
    };
    expect(normalize(pkt).fields[0]!.bits).toBe(0);
  });

  it("enum width and signed int width yield the declared bit count", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "e", name: "E", type: { kind: "enum", bits: 4, variants: {} } },
        { id: "i", name: "I", type: { kind: "int", bits: 16, signed: true } },
      ],
    };
    const n = normalize(pkt);
    expect(n.fields.find((f) => f.id === "e")!.bits).toBe(4);
    expect(n.fields.find((f) => f.id === "i")!.bits).toBe(16);
  });

  it("field byteOrder is copied onto the NormalizedField", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ id: "le", name: "LE", type: { kind: "int", bits: 16 }, byteOrder: "LE" }],
    };
    expect(normalize(pkt).fields[0]!.byteOrder).toBe("LE");
  });
});
