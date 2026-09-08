import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { parsePsdl } from "../src/yaml.js";

// Guard: every complete-document YAML example in the spec must validate cleanly.
// A "complete document" is a fenced ```yaml block that parses to a mapping with a
// top-level string `name` AND either a `body` array (a packet) or a `defs` mapping
// (a library document, D1). Pure illustrative fragments — a lone field, or a
// `name`/`abbrev` snippet with neither body nor defs — are skipped. This pins the
// class of regression where a normative rule (e.g. the D11 undeclared-ref check)
// starts rejecting the spec's own examples.
function completeDocs(specPath: string): { src: string; line: number }[] {
  const md = readFileSync(
    fileURLToPath(new URL(specPath, import.meta.url)),
    "utf8",
  );
  const lines = md.split("\n");
  const out: { src: string; line: number }[] = [];
  let inBlock = false,
    start = 0,
    buf: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (!inBlock && l.trim() === "```yaml") {
      inBlock = true;
      start = i + 1;
      buf = [];
      continue;
    }
    if (inBlock && l.trim() === "```") {
      inBlock = false;
      const src = buf.join("\n");
      let parsed: unknown;
      try {
        parsed = parseYaml(src);
      } catch {
        continue;
      }
      if (parsed && typeof parsed === "object") {
        const p = parsed as { name?: unknown; body?: unknown; defs?: unknown };
        const complete =
          typeof p.name === "string" &&
          (Array.isArray(p.body) ||
            (p.defs !== null && typeof p.defs === "object"));
        if (complete) out.push({ src, line: start });
      }
      continue;
    }
    if (inBlock) buf.push(l);
  }
  return out;
}

for (const spec of ["../spec/psdl-0.5.md", "../spec/psdl-0.5.ja.md"]) {
  describe(`spec examples validate — ${spec}`, () => {
    const docs = completeDocs(spec);
    it("finds complete-document examples", () => {
      expect(docs.length).toBeGreaterThan(0);
    });
    for (const { src, line } of docs) {
      it(`validates the document at line ${line}`, () => {
        const res = parsePsdl(src);
        if (!res.ok)
          throw new Error(
            `example at ${spec}:${line} failed validation:\n  ${res.errors.join("\n  ")}`,
          );
        expect(res.ok).toBe(true);
      });
    }
  });
}
