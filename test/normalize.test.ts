import { describe, expect, it } from "vitest";
import { berLenEnvKey, normalize, selectArm, varintBitsEnvKey } from "../src/normalize.js";
import { resolveLayout } from "../src/layout.js";
import { peekEnvKey } from "../src/expr.js";
import { resolveValueEntry } from "../src/values.js";
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

// C8/§5/§11.2: the reference implementation's bounded-OVER-consumption runtime
// error. (Under-consumption snap and the encrypted-wireBits cases are already
// pinned in the "bounded under-consumption advances to scope end" and
// "encrypted plaintext wireBits budget" describes below; this adds the missing
// bounded over-read error that the spec §11.2 row now documents.)
describe("normalize — bounded budget over-consumption (§5/§11.2, C8)", () => {
  it("over-consumed bounded budget is a runtime error", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 2 },
          fields: [{ id: "big", name: "B", type: { kind: "int", bits: 32 } }], // 4 > 2 bytes
        },
      ],
    };
    expect(() => normalize(pkt)).toThrow(/bounded scope "scope" over-consumed/);
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

  it("the encrypted region's meta rides on the wire-view blob (§5.4)", () => {
    const meta = { rfc: { defined: 9001, updates: [9999] }, section: "4" };
    const withMeta: Packet = {
      name: "t",
      body: [
        {
          kind: "encrypted",
          id: "payload",
          doc: "enc region",
          meta,
          contextNote: "note",
          plaintext: {
            id: "pt",
            fields: [{ id: "inE", name: "InE", type: { kind: "int", bits: 8 } }],
          },
        },
      ],
    };
    const n = normalize(withMeta, new Map(), { viewMode: "wire" });
    expect(n.fields).toHaveLength(1);
    const blob = n.fields[0]!;
    // doc and meta travel together on the same blob NormalizedField.
    expect(blob.doc).toBe("enc region");
    expect(blob.meta).toEqual(meta);
    expect(blob.encrypted).toBe(true);
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

  // C35/§5: the alignment reference point is the origin of THIS document's byte
  // stream (offset 0 of the normalize call), not an enclosing scope's start nor a
  // global capture buffer. An `align` inside a `bounded` scope therefore measures
  // from the document origin: starting at bit offset 20 (not a multiple of 32),
  // `align to: 32` lands on absolute offset 32, regardless of where the bounded
  // scope began.
  it("aligns to the document origin even inside a bounded scope (C35)", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "pre", name: "Pre", type: { kind: "int", bits: 20 } }, // origin 0..20
        {
          kind: "bounded",
          id: "scope",
          bytes: { kind: "lit", value: 8 },
          fields: [
            { kind: "align", to: 32 }, // 20 -> 32 (measured from document origin, not scope start)
            { id: "x", name: "X", type: { kind: "int", bits: 8 } },
          ],
        },
      ],
    };
    const n = normalize(pkt);
    // x lands at absolute offset 32: align measured the 12-bit gap from origin 0,
    // not from the bounded scope's own start (which was offset 20).
    expect(n.fields.find((f) => f.id === "x")!.absoluteBitOffset).toBe(32);
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

// C28/§4/§10.4: prevIter is STICKY across an iteration in which the referenced
// field was absent (its switch arm was not selected / its optional was not
// taken). The reference implementation overwrites the prevIter slot only when
// the field was actually present in the immediately preceding iteration; an
// absent prior iteration leaves the last present value in place (it does NOT
// reset to the §10.2 seed / 0). This test pins that behavior.
describe("normalize — prevIter sticky across an absent iteration (§4/§10.4, C28)", () => {
  it("keeps the last present value when the prior iteration omitted the field", () => {
    // element: flag (drives the optional via prevIter(flag)), optional{ val },
    // pad sized by prevIter(val).
    //  i0: prevIter(flag) = seed(flag default 1) != 0 -> val#0 present (=7).
    //  i1: prevIter(flag) = flag#0 = 0           -> optional NOT taken, val absent.
    //  i2: prevIter(flag) = flag#1 = 1           -> val#2 present.
    // pad in i2 reads prevIter(val): val#1 is absent, so the slot stays val#0=7
    // (sticky). A non-sticky impl would reset to the seed (val default 1).
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
              { id: "flag", name: "Flag", type: { kind: "int", bits: 8 }, defaultValue: 1 },
              {
                kind: "optional",
                when: { kind: "prevIter", field: "flag" },
                container: { id: "val", name: "Val", type: { kind: "int", bits: 8 }, defaultValue: 1 },
              },
              { id: "pad", name: "Pad", type: { kind: "bytes", n: { kind: "prevIter", field: "val" } } },
            ],
          },
        },
      ],
    };
    const env = new Map<string, number>([
      ["flag#0", 0], // makes i1's prevIter(flag) == 0 -> val absent in i1
      ["flag#1", 1], // i2 takes the optional again
      ["flag#2", 1],
      ["val#0", 7],
      ["val#2", 99],
    ]);
    const n = normalize(pkt, env);
    const pads = n.fields.filter((f) => f.id.startsWith("pad#"));
    // i0: prevIter(val) = seed (val default 1) -> 8 bits.
    expect(pads[0]!.bits).toBe(1 * 8);
    // i1: prevIter(val) = val#0 = 7 -> 56 bits.
    expect(pads[1]!.bits).toBe(7 * 8);
    // i2: val#1 was absent, so prevIter(val) stays sticky at val#0 = 7, NOT the
    // seed (1) -> 56 bits. This is the load-bearing assertion for C28.
    expect(pads[2]!.bits).toBe(7 * 8);
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

describe("normalize — align top-level cap vs unbounded (§5/§11.2, coverage #14)", () => {
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

describe("normalize — value dictionary & provenance propagation (§5.3/§5.4)", () => {
  it("copies field.values and field.meta verbatim into NormalizedField", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 },
        meta: { rfc: { defined: 791, updates: [2474, 3168] } },
        values: [{ value: 46, name: "EF", level: "must", meta: { rfc: 3246 } }],
      }],
    };
    const nf = normalize(pkt).fields[0]!;
    expect(nf.values).toEqual([{ value: 46, name: "EF", level: "must", meta: { rfc: 3246 } }]);
    expect(nf.meta).toEqual({ rfc: { defined: 791, updates: [2474, 3168] } });
  });

  it("omits values/meta when the source field has none", () => {
    const pkt: Packet = { name: "t", body: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }] };
    const nf = normalize(pkt).fields[0]!;
    expect(nf.values).toBeUndefined();
    expect(nf.meta).toBeUndefined();
  });
});

describe("normalize — group RFC provenance propagation (§5.4)", () => {
  it("copies Group.meta onto each child's groupMeta", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "tos", name: "DiffServ",
        meta: { rfc: { defined: 791, updates: [2474, 3168] } },
        children: [
          { id: "dscp", name: "DSCP", type: { kind: "int", bits: 6 } },
          { id: "ecn", name: "ECN", type: { kind: "int", bits: 2 } },
        ],
      }],
    };
    const fs = normalize(pkt).fields;
    expect(fs.map((f) => f.groupMeta)).toEqual([
      { rfc: { defined: 791, updates: [2474, 3168] } },
      { rfc: { defined: 791, updates: [2474, 3168] } },
    ]);
  });
  it("leaves groupMeta undefined when the group has no meta", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "g", name: "G",
        children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
      }],
    };
    expect(normalize(pkt).fields[0]!.groupMeta).toBeUndefined();
  });

  it("falls back to an OUTER group's meta when the inner group has none (§5.4)", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "outer", name: "Outer", meta: { rfc: 791 },
        children: [{
          kind: "group", id: "inner", name: "Inner",
          children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
        }],
      }],
    };
    const nf = normalize(pkt).fields[0]!;
    expect(nf.groupId).toBe("inner");
    expect(nf.groupMeta).toEqual({ rfc: 791 });
  });

  it("the innermost group's meta wins over an outer group's meta (§5.4)", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "outer", name: "Outer", meta: { rfc: 791 },
        children: [{
          kind: "group", id: "inner", name: "Inner", meta: { rfc: 2474 },
          children: [{ id: "a", name: "A", type: { kind: "int", bits: 8 } }],
        }],
      }],
    };
    expect(normalize(pkt).fields[0]!.groupMeta).toEqual({ rfc: 2474 });
  });
});

describe("normalize — wire-view encrypted blob attribution (§5/§5.4)", () => {
  it("carries groupId/groupName/groupMeta like any sibling leaf", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "gMeta", name: "G", meta: { rfc: 50 },
        children: [
          {
            kind: "encrypted", id: "gEnc", wireBits: { kind: "lit", value: 8 },
            plaintext: { id: "pt", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
          },
          { id: "tail", name: "Tail", type: { kind: "int", bits: 8 } },
        ],
      }],
    };
    const fs = normalize(pkt, new Map(), { viewMode: "wire" }).fields;
    const enc = fs.find((f) => f.id === "gEnc")!;
    expect(enc.encrypted).toBe(true);
    expect(enc.groupId).toBe("gMeta");
    expect(enc.groupName).toBe("G");
    expect(enc.groupMeta).toEqual({ rfc: 50 });
    expect(fs.find((f) => f.id === "tail")!.groupMeta).toEqual({ rfc: 50 });
  });

  it("carries the switch-arm key (switchCase)", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "disc", name: "D", type: { kind: "int", bits: 8 }, const: 1 },
        {
          kind: "switch", id: "sw", on: { kind: "ref", field: "disc" },
          cases: {
            "1": {
              id: "arm1",
              fields: [{
                kind: "encrypted", id: "sEnc", wireBits: { kind: "lit", value: 8 },
                plaintext: { id: "pt", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
              }],
            },
          },
        },
      ],
    };
    const enc = normalize(pkt, new Map(), { viewMode: "wire" }).fields.find((f) => f.id === "sEnc")!;
    expect(enc.switchCase).toBe("1");
  });

  it("qualifies the blob id per repeat iteration and records repeatIndex", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "repeat", id: "r", count: { kind: "lit", value: 2 },
        element: {
          id: "el",
          fields: [{
            kind: "encrypted", id: "rEnc", wireBits: { kind: "lit", value: 8 },
            plaintext: { id: "pt", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
          }],
        },
      }],
    };
    const fs = normalize(pkt, new Map(), { viewMode: "wire" }).fields;
    expect(fs.map((f) => [f.id, f.repeatIndex])).toEqual([["rEnc#0", 0], ["rEnc#1", 1]]);
  });

  it("prefixes the blob id inside a ref expansion (RefContainer id rule)", () => {
    const pkt: Packet = {
      name: "t",
      defs: {
        d: {
          id: "d",
          fields: [{
            kind: "encrypted", id: "dEnc", wireBits: { kind: "lit", value: 8 },
            plaintext: { id: "pt", fields: [{ id: "x", name: "X", type: { kind: "int", bits: 8 } }] },
          }],
        },
      },
      body: [
        { kind: "ref", ref: "d", id: "r1" },
        { kind: "ref", ref: "d", id: "r2" },
      ],
    };
    const fs = normalize(pkt, new Map(), { viewMode: "wire" }).fields;
    expect(fs.map((f) => f.id)).toEqual(["r1.dEnc", "r2.dEnc"]);
  });
});

describe("normalize — virtual name/doc/id (§5)", () => {
  it("keeps the authored name and doc on the virtual NormalizedField", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        { id: "a", name: "A", type: { kind: "int", bits: 8 } },
        { kind: "virtual", id: "v", name: "Virtual Name", doc: "virtual doc", expr: { kind: "lit", value: 3 } },
      ],
    };
    const nf = normalize(pkt).fields.find((f) => f.id === "v")!;
    expect(nf.virtual).toBe(true);
    expect(nf.name).toBe("Virtual Name");
    expect(nf.doc).toBe("virtual doc");
  });

  it("falls back to the id when no name is authored", () => {
    const pkt: Packet = {
      name: "t",
      body: [{ kind: "virtual", id: "v", expr: { kind: "lit", value: 1 } }],
    };
    const nf = normalize(pkt).fields[0]!;
    expect(nf.name).toBe("v");
    expect(nf.doc).toBeUndefined();
  });

  it("records the walk path as originalContainerPath, like every other emitted field", () => {
    // A virtual inside a group must share its siblings' container path so
    // (a) an LSP can trace it to the source container, and (b) the layout's
    // group collapse run is not split by the zero-width entry (§5.4).
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "group", id: "g2", name: "G2", meta: { rfc: 888 },
        children: [
          { id: "ga", name: "GA", type: { kind: "int", bits: 4 } },
          { kind: "virtual", id: "v1", expr: { kind: "ref", field: "ga" } },
          { id: "gb", name: "GB", type: { kind: "int", bits: 4 } },
        ],
      }],
    };
    const fs = normalize(pkt).fields;
    const ga = fs.find((f) => f.id === "ga")!;
    const v1 = fs.find((f) => f.id === "v1")!;
    expect(v1.originalContainerPath).toBe(ga.originalContainerPath);
    expect(v1.originalContainerPath).toBe("t/g2");
    expect(v1.groupId).toBe("g2");
    expect(v1.groupMeta).toEqual({ rfc: 888 });
  });

  it("qualifies the virtual id inside a repeat (no duplicate bare ids)", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "repeat", id: "r", count: { kind: "lit", value: 2 },
        element: {
          id: "el",
          fields: [
            { id: "x", name: "X", type: { kind: "int", bits: 8 } },
            { kind: "virtual", id: "vv", expr: { kind: "lit", value: 7 } },
          ],
        },
      }],
    };
    const fs = normalize(pkt).fields;
    expect(fs.map((f) => f.id)).toEqual(["x#0", "vv#0", "x#1", "vv#1"]);
  });
});

describe("normalize — values/meta propagation through nested paths (§5.3)", () => {
  it("switch-arm dependent field carries its arm-local values (ICMP two-stage form)", () => {
    const pkt: Packet = {
      name: "icmp",
      body: [
        { id: "type", name: "Type", type: { kind: "int", bits: 8 }, const: 3 },
        {
          kind: "switch", id: "sw", on: { kind: "ref", field: "type" },
          cases: {
            "3": {
              id: "unreach",
              fields: [{
                id: "code", name: "Code", type: { kind: "int", bits: 8 },
                meta: { rfc: 792 },
                values: [{ value: 3, name: "PortUnreach", label: "Port Unreachable" }],
              }],
            },
          },
        },
      ],
    };
    const code = normalize(pkt).fields.find((f) => f.id === "code")!;
    expect(code.switchCase).toBe("3");
    expect(code.meta).toEqual({ rfc: 792 });
    expect(resolveValueEntry(code.values, 3)?.name).toBe("PortUnreach");
  });

  it("ref-expanded fields keep their values and meta under the prefixed id", () => {
    const pkt: Packet = {
      name: "t",
      defs: {
        d: {
          id: "d",
          fields: [{
            id: "inner", name: "Inner", type: { kind: "int", bits: 8 },
            meta: { rfc: 111 },
            values: [{ value: 7, name: "SEVEN" }],
          }],
        },
      },
      body: [{ kind: "ref", ref: "d", id: "s" }],
    };
    const nf = normalize(pkt).fields.find((f) => f.id === "s.inner")!;
    expect(nf.meta).toEqual({ rfc: 111 });
    expect(resolveValueEntry(nf.values, 7)?.name).toBe("SEVEN");
  });

  it("repeat-iteration fields keep values and the enclosing group's meta", () => {
    const pkt: Packet = {
      name: "t",
      body: [{
        kind: "repeat", id: "r", count: { kind: "lit", value: 2 },
        element: {
          id: "el",
          fields: [{
            kind: "group", id: "g", name: "G", meta: { rfc: 555 },
            children: [{
              id: "v", name: "V", type: { kind: "int", bits: 8 },
              values: [{ value: 1, name: "ONE" }],
            }],
          }],
        },
      }],
    };
    const fs = normalize(pkt).fields;
    expect(fs.map((f) => f.id)).toEqual(["v#0", "v#1"]);
    for (const nf of fs) {
      expect(nf.groupMeta).toEqual({ rfc: 555 });
      expect(resolveValueEntry(nf.values, 1)?.name).toBe("ONE");
    }
  });
});

describe("normalize — region meta is source-AST only (§5.4 carve-out)", () => {
  it("switch-arm / repeat-element / optional / defs meta does not propagate to normalized fields", () => {
    // §5.4: these containers are transparent in the flat normalized model, so
    // their region meta stays documentation-grade provenance in the source
    // AST. Fields inside them remain attributable via switchCase /
    // repeatIndex / originalContainerPath instead.
    const pkt: Packet = {
      name: "t",
      defs: {
        d: {
          id: "d",
          meta: { rfc: 333 },
          fields: [{ id: "df", name: "DF", type: { kind: "int", bits: 8 } }],
        },
      },
      body: [
        { id: "disc", name: "Disc", type: { kind: "int", bits: 8 }, const: 1 },
        {
          kind: "switch", id: "sw", on: { kind: "ref", field: "disc" },
          cases: {
            "1": {
              id: "arm1", meta: { rfc: 792 },
              fields: [{ id: "swf", name: "SWF", type: { kind: "int", bits: 8 } }],
            },
          },
        },
        {
          kind: "repeat", id: "r", count: { kind: "lit", value: 1 },
          element: {
            id: "el", meta: { rfc: 555 },
            fields: [{ id: "rf", name: "RF", type: { kind: "int", bits: 8 } }],
          },
        },
        {
          kind: "optional", when: { kind: "lit", value: 1 }, meta: { rfc: 444 },
          container: { id: "of", name: "OF", type: { kind: "int", bits: 8 } },
        },
        { kind: "ref", ref: "d", id: "x" },
      ],
    };
    const fs = normalize(pkt).fields;
    // No emitted field carries any of the region metas…
    const rfcs = fs.flatMap((f) => [f.meta, f.groupMeta]).filter((m) => m !== undefined);
    expect(rfcs).toEqual([]);
    // …but every region's fields stay attributable to their source region.
    expect(fs.find((f) => f.id === "swf")!.switchCase).toBe("1");
    expect(fs.find((f) => f.id === "rf#0")!.repeatIndex).toBe(0);
    expect(fs.find((f) => f.id === "x.df")).toBeDefined();
    expect(fs.find((f) => f.id === "of")).toBeDefined();
  });
});

// D7: a single-field shared value-dictionary def, reused via two `ref`s. The
// expanded leaf carries the source field's values/meta unchanged (the new §5.3
// propagation MUST), while the def's own NamedStruct.meta does NOT appear.
describe("normalize — shared value-dictionary def propagation (§5.3, D7)", () => {
  const pkt: Packet = {
    name: "ethertype-share",
    body: [
      { kind: "ref", ref: "etherType", id: "ethType", name: "EtherType" },
      { kind: "ref", ref: "etherType", id: "innerType", name: "Inner EtherType" },
    ],
    defs: {
      etherType: {
        id: "etherType",
        doc: "IANA EtherType registry (single field, shared)",
        // def-level meta is source-AST-only and must NOT reach NormalizedField.
        meta: { rfc: 9999, section: "def-only" },
        fields: [{
          id: "value", name: "EtherType", type: { kind: "int", bits: 16 },
          category: "type", display: "hex",
          meta: { rfc: 7042, section: "2.3.1" },
          values: [
            { value: 0x0800, name: "IPv4", label: "Internet Protocol v4", meta: { rfc: 894 } },
            { value: 0x0806, name: "ARP", label: "Address Resolution Protocol", meta: { rfc: 826 } },
            { value: 0x86dd, name: "IPv6", label: "Internet Protocol v6", meta: { rfc: 8200 } },
            { range: [0x0000, 0x05dc], name: "LEN", label: "IEEE 802.3 length (<=1500)" },
            { pattern: "1111111111111111", name: "RESERVED", label: "Reserved" },
          ],
        }],
      },
    },
  };

  it("carries values+meta through both ref expansions at the expanded leaf id (a)", () => {
    const fs = normalize(pkt).fields;
    const a = fs.find((f) => f.id === "ethType.value")!;
    const b = fs.find((f) => f.id === "innerType.value")!;
    expect(a.values?.length).toBe(5);
    expect(b.values?.length).toBe(5);
    expect(a.meta).toEqual({ rfc: 7042, section: "2.3.1" });
    expect(b.meta).toEqual({ rfc: 7042, section: "2.3.1" });
  });

  it("resolves value/range/pattern entries correctly via resolveValueEntry (b)", () => {
    const a = normalize(pkt).fields.find((f) => f.id === "ethType.value")!;
    const v = a.values!;
    expect(resolveValueEntry(v, 0x0800)?.name).toBe("IPv4");   // exact
    expect(resolveValueEntry(v, 0x0100)?.name).toBe("LEN");    // range
    expect(resolveValueEntry(v, 0xffff)?.name).toBe("RESERVED"); // pattern
  });

  it("does NOT surface the def's own NamedStruct.meta on any NormalizedField (c, MUST boundary)", () => {
    const fs = normalize(pkt).fields;
    // The only meta present is the field-declared one; the def's { section: "def-only" } never appears.
    for (const f of fs) {
      expect(f.meta?.section).not.toBe("def-only");
      expect(f.meta?.rfc).not.toBe(9999);
    }
  });
});

// D9: checksum binding (algorithm, covers, pseudoHeader, params incl. width)
// rides through to the NormalizedField for codegen/LSP.
describe("normalize — checksum binding propagation (§8, D9)", () => {
  it("carries checksumAlgorithm/checksumCovers/checksumParams onto the NormalizedField", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          id: "crc", name: "CRC-64", type: { kind: "int", bits: 64 }, category: "checksum",
          checksumAlgorithm: "crc64-ecma182", checksumCovers: ["data"],
          checksumParams: { polynomial: "0xAD93D23594C935A9", width: 64 },
        },
        { id: "data", name: "Data", type: { kind: "bytes", n: { kind: "lit", value: 8 } } },
      ],
    };
    const crc = normalize(pkt).fields.find((f) => f.id === "crc")!;
    expect(crc.checksumAlgorithm).toBe("crc64-ecma182");
    expect(crc.checksumCovers).toEqual(["data"]);
    expect(crc.checksumParams).toEqual({ polynomial: "0xAD93D23594C935A9", width: 64 });
  });
});

// D6: headerProtected may name a plaintext-external field declared earlier in
// the same body (QUIC long-header: firstByte and packetNumber). The tag rides
// on the already-emitted top-level field in both views.
describe("normalize — plaintext-external headerProtected (§5, D6)", () => {
  const quic: Packet = {
    name: "quic",
    body: [
      { id: "firstByte", name: "First Byte", type: { kind: "int", bits: 8 } },
      { id: "version", name: "Version", type: { kind: "int", bits: 32 } },
      { id: "packetNumber", name: "Packet Number", type: { kind: "bytes", n: { kind: "lit", value: 4 } } },
      {
        kind: "encrypted", id: "payload", contextNote: "AEAD-protected payload",
        wireBits: { kind: "lit", value: 800 },
        plaintext: { id: "frames", fields: [{ id: "data", name: "Frame Data", type: { kind: "bytes", n: { kind: "remaining" } } }] },
        headerProtected: ["firstByte", "packetNumber"],
      },
    ],
  };
  it("tags the plaintext-external header fields in wire view", () => {
    const fs = normalize(quic, new Map(), { viewMode: "wire" }).fields;
    expect(fs.find((f) => f.id === "firstByte")!.headerProtected).toBe(true);
    expect(fs.find((f) => f.id === "packetNumber")!.headerProtected).toBe(true);
    expect(fs.find((f) => f.id === "version")!.headerProtected).toBeUndefined();
  });
  it("tags the same fields in semantic view", () => {
    const fs = normalize(quic, new Map(), { viewMode: "semantic" }).fields;
    expect(fs.find((f) => f.id === "firstByte")!.headerProtected).toBe(true);
    expect(fs.find((f) => f.id === "packetNumber")!.headerProtected).toBe(true);
  });
});

// D3: a delimiter-terminated bytes field resolves its length from a qualified
// seed-injection key (§3/§10.7); with no injection it lays out as 0 bytes.
describe("normalize — bytes delimiter length (§3/§10.7, D3)", () => {
  const pkt: Packet = {
    name: "http",
    body: [
      { id: "requestLine", name: "Request line", display: "ascii", type: { kind: "bytes", n: { delimiter: [13, 10] } } },
      { id: "rest", name: "Rest", type: { kind: "bytes", n: { kind: "remaining" } } },
    ],
  };
  it("uses the injected qualified length and keeps it distinct from the value slot", () => {
    // "GET /\r\n" = 7 bytes including CRLF.
    const env = new Map<string, number>([
      ["__bytesDelimLen__requestLine", 7],
      // env[id] is the field value slot; it must NOT be confused with the length.
      ["requestLine", 999],
    ]);
    const fs = normalize(pkt, env, { viewMode: "wire", totalBits: 100 * 8 }).fields;
    const rl = fs.find((f) => f.id === "requestLine")!;
    expect(rl.bits).toBe(7 * 8);
  });
  it("lays out as 0 bytes (unknown) with no injection (static preview)", () => {
    const fs = normalize(pkt, new Map(), { viewMode: "wire", totalBits: 100 * 8 }).fields;
    expect(fs.find((f) => f.id === "requestLine")!.bits).toBe(0);
  });
});

// D4: subfields ride through to the NormalizedField for LSP/codegen value
// decode. Render sub-cell positioning is deferred (not guaranteed in 0.5).
describe("normalize — subfields propagation (§12, D4)", () => {
  it("copies subfields verbatim onto the NormalizedField", () => {
    const pkt: Packet = {
      name: "ieee802154", byteOrder: "LE",
      body: [{
        id: "fcf", name: "Frame Control", type: { kind: "int", bits: 16 }, display: "hex",
        subfields: [
          { id: "frameType", name: "Frame Type", mask: 0x0007, category: "type" },
          { id: "srcAddrMode", name: "Src Addr Mode", mask: 0xc000, category: "type" },
        ],
      }],
    };
    const fcf = normalize(pkt).fields.find((f) => f.id === "fcf")!;
    expect(fcf.subfields?.length).toBe(2);
    expect(fcf.subfields?.[0]).toEqual({ id: "frameType", name: "Frame Type", mask: 0x0007, category: "type" });
  });

  it("exposes mask subfields via NormalizedField.subfields but NOT via ResolvedLayout (§12 boundary)", () => {
    const pkt: Packet = {
      name: "ieee802154", byteOrder: "LE", rowBits: 16,
      body: [{
        id: "fcf", name: "Frame Control", type: { kind: "int", bits: 16 },
        subfields: [{ id: "frameType", name: "Frame Type", mask: 0x0007 }],
      }],
    };
    // Present on the normalized field…
    expect(normalize(pkt).fields.find((f) => f.id === "fcf")!.subfields?.length).toBe(1);
    // …and intentionally absent from the layout (wire-render position not guaranteed in 0.5).
    const cell = resolveLayout(pkt).cells.find((c) => c.field.id === "fcf")!;
    expect(cell.field.subfields).toBeUndefined();
    expect(cell.subCells).toBeUndefined();
  });
});
