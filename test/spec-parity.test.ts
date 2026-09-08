// EN/JA spec parity.
//
// `psdl-0.5.md` is normative and `psdl-0.5.ja.md` is a translation, so they are
// allowed to differ in prose — but not in STRUCTURE. Every divergence found in
// the audit was structural: a subsection that existed only in one language, a
// table row deleted from one side, an example truncated in translation. Those
// are mechanically checkable, and nothing was checking them: the existing
// spec-examples test extracts under conditions strict enough that it guarded
// exactly one YAML block per language.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const EN = readFileSync(new URL("../spec/psdl-0.5.md", import.meta.url), "utf8");
const JA = readFileSync(new URL("../spec/psdl-0.5.ja.md", import.meta.url), "utf8");

/** Heading levels in document order, ignoring anything inside a code fence. */
function headingLevels(md: string): number[] {
  const out: number[] = [];
  let inFence = false;
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = /^(#+)\s+\S/.exec(line);
    if (m) out.push(m[1].length);
  }
  return out;
}

/** Leading section numbers (`12`, `11.1`) in document order. */
function sectionNumbers(md: string): string[] {
  const out: string[] = [];
  let inFence = false;
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = /^#+\s+(\d+(?:\.\d+)*)\.?\s/.exec(line);
    if (m) out.push(m[1]);
  }
  return out;
}

/**
 * Fenced code blocks reduced to their CODE: blank lines, whole-line comments
 * and trailing `# …` comments are dropped, because comments are translated.
 * What must match is the YAML itself.
 */
function codeBlocks(md: string): string[] {
  const out: string[] = [];
  let cur: string[] | null = null;
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) {
      if (cur === null) cur = [];
      else { out.push(cur.join("\n")); cur = null; }
      continue;
    }
    if (cur !== null) {
      let t = line.replace(/\s+#.*$/, "").trim();
      // `doc:` / `label:` / `description:` carry prose, which IS translated.
      // Keep the key so a dropped line still shows up; drop the value.
      t = t.replace(/^(doc|label|description|name):\s.*$/, "$1:");
      // `<...>` placeholders describe a value in prose, so they are translated.
      t = t.replace(/<[^>]*>/g, "<>");
      if (t !== "" && !t.startsWith("#")) cur.push(t);
    }
  }
  return out;
}

describe("spec parity — EN is normative, JA is a translation", () => {
  it("declares which document governs", () => {
    expect(EN).toMatch(/This document is normative/);
    expect(JA).toMatch(/参考訳であり、規範ではない/);
  });

  it("has the same heading structure", () => {
    // Catches a subsection that exists in only one language — the §12
    // "Applicability by type" case, which shifted every later heading by one.
    expect(headingLevels(JA)).toEqual(headingLevels(EN));
  });

  it("numbers its sections identically", () => {
    expect(sectionNumbers(JA)).toEqual(sectionNumbers(EN));
  });

  it("carries the same code examples", () => {
    // Comments are translated, so they are stripped; the YAML itself must not
    // be abridged. Catches an example truncated to "the interesting lines".
    expect(codeBlocks(JA)).toEqual(codeBlocks(EN));
  });

  it("has the same number of §11.1 validation-error rows", () => {
    // 0.5 identifies a diagnostic by "§ number + the row's text", so a row
    // present in one language and not the other is a diagnostic that cannot be
    // named consistently.
    const rows = (md: string, marker: string, cell: string): number => {
      const start = md.indexOf(marker);
      expect(start).toBeGreaterThan(-1);
      let n = 0;
      for (const line of md.slice(start).split("\n")) {
        if (/^#+\s+11\.2/.test(line)) break;
        if (line.startsWith("|") && line.includes(cell)) n++;
      }
      return n;
    };
    expect(rows(JA, "11.1", "検証エラー")).toBe(rows(EN, "11.1", "Validation error"));
  });
});
