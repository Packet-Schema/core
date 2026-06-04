import { describe, expect, it } from "vitest";
import { parsePsdl } from "../src/yaml.js";

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

  it("preserves eos and auto sentinels", () => {
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
          type: { kind: bytes, n: auto }
`;
    const r = parsePsdl(src);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rep = r.packet.body[0] as { count: unknown; element: { fields: { type: { n: unknown } }[] } };
    expect(rep.count).toBe("eos");
    expect(rep.element.fields[0]!.type.n).toBe("auto");
  });

  it("reports validation errors", () => {
    const r = parsePsdl(`name: t\nbody:\n  - id: "1bad"\n    name: X\n    type: { kind: int, bits: 8 }`);
    expect(r.ok).toBe(false);
  });
});
