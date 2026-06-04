import type { Container, Field } from "./types.js";

export function isField(c: Container): c is Field {
  return !("kind" in c) || c.kind === "field" || c.kind === undefined;
}
