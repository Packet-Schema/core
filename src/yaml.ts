// YAML primary I/O — PSDL の canonical authoring フォーマット。
// JSON は YAML のサブセットなので parsePsdl は JSON 文字列も受け付ける。

import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { validatePacket } from "./validate.js";
import type { Packet } from "./types.js";

export type ParseResult =
  | { ok: true; packet: Packet }
  | { ok: false; errors: string[] };

export function parsePsdl(source: string): ParseResult {
  let raw: unknown;
  try {
    raw = parseYaml(source);
  } catch (e) {
    return { ok: false, errors: [`YAML parse error: ${String(e)}`] };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, errors: ["PSDL document must be a YAML mapping."] };
  }
  const packet = raw as Packet;
  const errors = validatePacket(packet);
  if (errors.length > 0) {
    return { ok: false, errors: errors.map((e) => e.message) };
  }
  return { ok: true, packet };
}

export function stringifyPsdl(packet: Packet): string {
  return stringifyYaml(packet, {
    lineWidth: 0,
    defaultKeyType: "PLAIN",
    defaultStringType: "PLAIN",
  });
}
