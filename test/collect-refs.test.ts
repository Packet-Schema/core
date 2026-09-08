import { describe, expect, it } from "vitest";
import { collectPsdlRefs } from "../src/collect-refs.js";
import { lit, op, ref } from "../src/expr.js";
import type { Packet } from "../src/types.js";

describe("collectPsdlRefs", () => {
  it("gathers field-id refs from every container kind and slot", () => {
    const pkt: Packet = {
      name: "t",
      defs: {
        sub: {
          id: "sub",
          fields: [
            { id: "s", name: "S", type: { kind: "bytes", n: ref("dlen") } },
          ],
        },
      },
      body: [
        // bytes.n
        { id: "data", name: "D", type: { kind: "bytes", n: ref("len") } },
        // switch.on
        {
          kind: "switch",
          id: "sw",
          on: ref("proto"),
          cases: { "1": { id: "a", fields: [] } },
        },
        // repeat count.until
        {
          kind: "repeat",
          id: "r",
          count: { until: op("==", ref("flag"), lit(0)) },
          element: { id: "el", fields: [] },
        },
        // optional.when
        {
          kind: "optional",
          when: ref("present"),
          container: { id: "opt", name: "O", type: { kind: "int", bits: 8 } },
        },
        // bounded.bytes + a ref into a def
        {
          kind: "bounded",
          id: "bnd",
          bytes: ref("cap"),
          fields: [{ kind: "ref", ref: "sub", id: "subInst" }],
        },
      ],
      constraints: [{ lhs: ref("x"), rhs: ref("y") }],
    };
    const got = collectPsdlRefs(pkt);
    expect(got).toEqual(
      new Set(["len", "proto", "flag", "present", "cap", "dlen", "x", "y"]),
    );
  });

  it("contributes no ref for an eos repeat count", () => {
    const pkt: Packet = {
      name: "t",
      body: [
        {
          kind: "repeat",
          id: "r",
          count: "eos",
          element: {
            id: "el",
            fields: [{ id: "v", name: "V", type: { kind: "int", bits: 8 } }],
          },
        },
      ],
    };
    expect(collectPsdlRefs(pkt)).toEqual(new Set());
  });
});
