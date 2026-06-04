import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";

const schemaPath = fileURLToPath(new URL("../schemas/psdl-0.5.yaml", import.meta.url));
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
        { id: "version", name: "Version", type: { kind: "int", bits: 4 }, const: 4, category: "identifier" },
        { id: "ihl", name: "IHL", type: { kind: "int", bits: 4 }, category: "length" },
        { kind: "ref", ref: "ipv4Addr", id: "src", name: "Source" },
        {
          kind: "switch", id: "payload", on: { kind: "ref", field: "ihl" },
          cases: {
            "6": { id: "tcp", fields: [{ id: "sp", name: "SP", type: { kind: "int", bits: 16 } }] },
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
          kind: "bounded", id: "scope", bytes: { kind: "lit", value: 8 },
          fields: [{ id: "x", name: "X", type: { kind: "bytes", n: { kind: "remaining" } } }],
        },
      ],
    };
    const ok = validate(pkt);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });
});
