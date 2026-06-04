// layout.ts — renderer に依存しない bit-grid 展開。
// Cell / LayoutField / ResolvedLayout はすべて types.ts で定義。

import type {
  Cell,
  LayoutField,
  LayoutSubField,
  NormalizedField,
  PacketEnv,
  Packet as PsdlPacket,
  ResolvedLayout,
  SubCell,
  ViewMode,
} from "./types.js";
import { initialEnv, normalize } from "./normalize.js";

export type LayoutOptions = {
  env?: PacketEnv;
  viewMode?: ViewMode;
};

function resolveRowBits(packet: PsdlPacket): number {
  return packet.rendererHints?.rowBits ?? packet.rowBits ?? 0;
}

export function resolveLayout(
  packet: PsdlPacket,
  options: LayoutOptions = {},
): ResolvedLayout {
  const rowBits = resolveRowBits(packet);
  if (!Number.isInteger(rowBits) || rowBits <= 0) {
    throw new Error(
      `resolveLayout: rowBits must be a positive integer; got ${String(rowBits)}.`,
    );
  }
  const env: PacketEnv = new Map(options.env ?? initialEnv(packet));
  const viewMode: ViewMode = options.viewMode ?? "wire";
  const norm = normalize(packet, env, { viewMode });
  const cells: Cell[] = [];
  let bitPos = 0;
  const groups = groupConsecutiveByContainer(norm.fields);
  for (const g of groups) {
    if (g.kind === "flat") {
      const nf = g.field;
      const field: LayoutField = {
        id: nf.id,
        name: nf.name,
        bits: nf.bits,
        ...(nf.category ? { category: nf.category } : {}),
        ...(nf.doc ? { description: nf.doc } : {}),
      };
      bitPos = emitField(field, nf, bitPos, rowBits, cells);
      continue;
    }
    const totalBits = g.children.reduce((a, f) => a + f.bits, 0);
    if (totalBits === 0) continue;
    const subfields: LayoutSubField[] = g.children.map((c) => ({
      id: c.id.replace(/#\d+$/, ""),
      name: c.name,
      bits: c.bits,
      ...(c.doc ? { description: c.doc } : {}),
    }));
    const field: LayoutField = {
      id: g.parentId,
      name: g.parentName,
      bits: totalBits,
      subfields,
      ...(g.children.find((c) => c.category)?.category
        ? { category: g.children.find((c) => c.category)!.category! }
        : {}),
    };
    const allEncrypted = g.children.every((c) => c.encrypted);
    const sharedParentId =
      g.children[0]?.encryptedParentId &&
      g.children.every((c) => c.encryptedParentId === g.children[0]?.encryptedParentId)
        ? g.children[0].encryptedParentId
        : undefined;
    const allHeaderProtected = g.children.every((c) => c.headerProtected);
    const sharedByteOrder =
      g.children[0]?.byteOrder &&
      g.children.every((c) => c.byteOrder === g.children[0]?.byteOrder)
        ? g.children[0].byteOrder
        : undefined;
    const first = g.children[0]!;
    const proxy: NormalizedField = {
      ...first,
      id: g.parentId,
      name: g.parentName,
      bits: totalBits,
      ...(allEncrypted ? { encrypted: true as const } : {}),
      ...(sharedParentId !== undefined ? { encryptedParentId: sharedParentId } : {}),
      ...(sharedParentId ? { encryptedContextNote: first.encryptedContextNote } : {}),
      ...(allHeaderProtected ? { headerProtected: true as const } : {}),
      ...(sharedByteOrder !== undefined ? { byteOrder: sharedByteOrder } : {}),
    };
    bitPos = emitField(field, proxy, bitPos, rowBits, cells, g.children);
  }
  return { cells, totalBits: norm.totalBits };
}

type GroupedRun =
  | { kind: "flat"; field: NormalizedField }
  | { kind: "collapsed"; parentId: string; parentName: string; children: NormalizedField[] };

function groupConsecutiveByContainer(fields: NormalizedField[]): GroupedRun[] {
  const out: GroupedRun[] = [];
  let i = 0;
  while (i < fields.length) {
    const f = fields[i]!;
    if (!f.groupId) { out.push({ kind: "flat", field: f }); i++; continue; }
    const groupId = f.groupId;
    const groupPath = f.originalContainerPath;
    const run: NormalizedField[] = [f];
    let j = i + 1;
    while (
      j < fields.length &&
      fields[j]!.groupId === groupId &&
      fields[j]!.originalContainerPath === groupPath
    ) {
      run.push(fields[j]!);
      j++;
    }
    if (run.length === 1) { out.push({ kind: "flat", field: f }); i = j; continue; }
    out.push({ kind: "collapsed", parentId: groupId, parentName: f.groupName ?? groupId, children: run });
    i = j;
  }
  return out;
}

function emitField(
  field: LayoutField,
  nf: NormalizedField,
  bitPos: number,
  rowBits: number,
  cells: Cell[],
  childNFs?: NormalizedField[],
): number {
  const bits = nf.bits;
  if (bits === 0) return bitPos;
  let remaining = bits;
  let segmentIndex = 0;
  const totalSegments = computeSegmentCount(bitPos, bits, rowBits);
  while (remaining > 0) {
    const row = Math.floor(bitPos / rowBits);
    const colInRow = bitPos % rowBits;
    const take = Math.min(remaining, rowBits - colInRow);
    const cell: Cell = {
      field,
      bitsTotal: bits,
      row,
      startBit: colInRow,
      endBit: colInRow + take - 1,
      segmentIndex,
      totalSegments,
      isFirst: segmentIndex === 0,
      isLast: remaining === take,
      fieldStartOffset: bits - remaining,
      fieldEndOffset: bits - remaining + take - 1,
    };
    if (nf.encrypted) cell.encrypted = true;
    if (nf.encryptedParentId !== undefined) cell.encryptedParentId = nf.encryptedParentId;
    if (nf.encryptedContextNote !== undefined) cell.encryptedContextNote = nf.encryptedContextNote;
    if (nf.headerProtected) cell.headerProtected = true;
    if (nf.byteOrder) cell.byteOrder = nf.byteOrder;
    if (field.subfields && field.subfields.length > 0) {
      cell.subCells = buildSubCells(field, field.subfields, cell.fieldStartOffset, cell.fieldEndOffset, colInRow, childNFs);
    }
    cells.push(cell);
    remaining -= take;
    bitPos += take;
    segmentIndex++;
  }
  return bitPos;
}

function buildSubCells(
  parentField: LayoutField,
  subfields: LayoutSubField[],
  fieldStartOffset: number,
  fieldEndOffset: number,
  segmentColInRow: number,
  childNFs?: NormalizedField[],
): SubCell[] {
  const out: SubCell[] = [];
  let cursor = 0;
  for (let i = 0; i < subfields.length; i++) {
    const sf = subfields[i]!;
    const subStart = cursor;
    const subEnd = cursor + sf.bits;
    cursor = subEnd;
    const lo = Math.max(subStart, fieldStartOffset);
    const hi = Math.min(subEnd, fieldEndOffset + 1);
    if (lo >= hi) continue;
    const startBit = segmentColInRow + (lo - fieldStartOffset);
    const childNF = childNFs?.[i];
    const sub: SubCell = {
      parentField,
      subfield: sf,
      id: `${parentField.id}:${sf.id}`,
      startBit,
      endBit: startBit + (hi - lo) - 1,
      isFirst: lo === subStart,
      isLast: hi === subEnd,
      bitsTotal: sf.bits,
    };
    if (childNF?.encrypted) sub.encrypted = true;
    if (childNF?.encryptedParentId !== undefined) sub.encryptedParentId = childNF.encryptedParentId;
    if (childNF?.encryptedContextNote !== undefined) sub.encryptedContextNote = childNF.encryptedContextNote;
    if (childNF?.headerProtected) sub.headerProtected = true;
    if (childNF?.byteOrder) sub.byteOrder = childNF.byteOrder;
    out.push(sub);
  }
  return out;
}

function computeSegmentCount(startPos: number, bits: number, rowBits: number): number {
  let remaining = bits;
  let pos = startPos;
  let count = 0;
  while (remaining > 0) {
    const take = Math.min(remaining, rowBits - (pos % rowBits));
    remaining -= take;
    pos += take;
    count++;
  }
  return count;
}
