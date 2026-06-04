# PSDL 0.5 — Packet Schema Definition Language

A YAML-based language for describing the wire format of network protocol packets.
The formal JSON Schema is at `schemas/psdl-0.5.yaml`.

---

## 1. Document structure

A PSDL document is a single YAML mapping representing one packet type.

```yaml
version: "0.5"
name: ipv4
description: Internet Protocol version 4
byteOrder: BE
rendererHints:
  rowBits: 32
meta:
  rfc: 791
  section: "3.1"
  aliases: [ip]
abbrev: ip
imports:
  - source: common/addresses.psdl
    as: addr
body:
  - id: version
    name: Version
    type: { kind: int, bits: 4 }
    category: identifier
    const: 4
  - id: ihl
    name: IHL
    type: { kind: int, bits: 4 }
    category: length
constraints:
  - lhs: { kind: ref, field: totalLength }
    rhs:
      kind: op
      op: "+"
      a: { kind: op, op: "*", a: { kind: ref, field: ihl }, b: { kind: lit, value: 4 } }
      b: { kind: ref, field: dataLength }
    doc: totalLength = header + data
defs: {}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique packet identifier (globally unique within a packet set) |
| `body` | yes | Ordered list of containers |
| `version` | no | PSDL version string (recommended; see §15) |
| `description` | no | Human-readable summary |
| `byteOrder` | no | Default byte order: `BE` or `LE` (default `BE`) |
| `rendererHints` | no | Display-only metadata |
| `meta` | no | RFC and alias metadata for tooling |
| `abbrev` | no | Protocol filter name (e.g. for Wireshark). Defaults to `name` |
| `constraints` | no | Equality constraints for back-propagation |
| `defs` | no | Named struct definitions for reuse |
| `imports` | no | Cross-file def imports (see §1.2) |

### 1.1 Packet metadata (`meta`)

```yaml
meta:
  rfc: 791          # RFC number (integer)
  section: "3.1"    # RFC section (string)
  aliases: [ip, ipv4]   # alternative names for this packet type
```

All fields are optional. Used by codegen, Chrome extension, and LSP for
disambiguation and cross-reference.

### 1.2 Cross-file imports (`imports`)

The `imports` list makes `defs` from other PSDL files available under a
namespace prefix. This is the mechanism for sharing common structs (IPv4
addresses, MAC addresses, TLS extension headers, etc.) across protocol files
without copy-pasting.

```yaml
imports:
  - source: common/addresses.psdl
    as: addr
  - source: "@packet-schema/presets/tls-types"
    as: tls
```

After import, the imported defs are accessible with the prefix:
`ref: addr.ipv4Addr`. Expanded ids follow the same dotting rules:
`addr.ipv4Addr.oct0`.

**Rules:**

- `source` is an opaque path string. Resolution strategy (filesystem path,
  package registry, URL) is the concern of the tool layer.
- `as` defines the namespace prefix; must match `[a-zA-Z][a-zA-Z0-9_]*`.
- Two imports must not share the same `as` prefix — validation error.
- Circular imports (A imports B which imports A) are a validation error.
- Imported defs are read-only; a document cannot re-declare an imported name.
- If a `source` cannot be resolved, it is a validation error.
- **Imports are not re-exported.** A document sees only the defs declared in
  the files it directly lists in its own `imports`. If file B imports C under
  prefix `c`, that prefix is **not** visible to A after A imports B. If A
  needs defs from C, A must list C explicitly in its own `imports`. A `ref`
  target resolved only through a transitive import (not directly listed in
  the importing document) is a validation error.

### 1.3 Imported name visibility

The following rules govern how imported def names are visible in expressions,
`checksumCovers`, and `constraints`:

- Imported def names used as `ref`-container ids in `body` expand their fields
  into the local namespace under the **instantiation id**, not the import
  prefix. For example, `ref: addr.ipv4Addr` with `id: src` expands to
  `src.oct0`, `src.oct1`, etc. — not `addr.ipv4Addr.oct0`.
- `checksumCovers` accepts both local instantiation ids (e.g. `src`) and
  dotted leaf ids (e.g. `src.oct0`) regardless of whether the def originated
  from an import or was declared locally in `defs`.
- Using an import-qualified def name (e.g. `addr.ipv4Addr`) directly in
  `checksumCovers` is a validation error. Use the instantiation id (e.g.
  `src`) or its dotted leaf form (e.g. `src.oct0`) instead.
- Constraint expressions may reference any field reachable by its expanded id,
  including fields that originate from imported defs, using the instantiation
  prefix form (e.g. `src.oct0`).

---

## 2. Field identifiers

Field `id` values are the primary handle used in expressions, cross-references,
and protocol linking.

- Allowed characters for authored ids: `[a-zA-Z][a-zA-Z0-9_-]*`
- `.` is **reserved** as the ref-expansion separator and must not appear in
  an authored id.
- After ref expansion, virtual ids of the form `{ref.id}.{field.id}` are
  generated. These dotted forms are used in expressions and `checksumCovers`
  but are never authored directly in YAML.
- Import namespace prefixes (§1.2) further qualify def names: `addr.ipv4Addr`.
- Ids must be unique within their visible scope (see §10.1 for scoping rules).

---

## 3. Wire types

Every `Field` has a `type` describing how bits on the wire map to a value.

### `int` — fixed-width integer

```yaml
type: { kind: int, bits: 16 }              # unsigned 16-bit
type: { kind: int, bits: 8, signed: true } # signed 8-bit
```

### `bits` — raw bit field

No numeric interpretation. Used for flag groups or padding.
A `bits` field that is a whole number of bytes wide (n a multiple of 8, > 8)
**and** begins on a byte boundary follows the packet-level `byteOrder` for its
multi-byte read; a `bits` field of any other width, or one that begins or ends
mid-byte, is a raw MSB-first bit run with no byte-order swap (see §12 for the
full rules and the distinction from `int`/`enum`).

```yaml
type: { kind: bits, n: 3 }
```

### `bytes` — variable-length byte array

Length is given by an expression (result is in bytes).
If the expression evaluates to `0`, the field occupies zero bytes.

To consume all remaining bytes of the immediately enclosing scope-providing
container (a `bounded` scope, an `encrypted.plaintext` struct, or the
top-level `body`), use `n: { kind: remaining }` (§4). To leave a fixed number
of bytes at the end of a region for end-anchored fields, size the data field
`remaining - <constByteCount>` and place the end-anchored fields as ordinary
fields after it. The `remaining` primitive may be used in `bytes.n` at any
position within the scope — mid-scope, in last position, or inside compound
expressions such as `cond` (see §4 for the definition of data-consuming
containers and the position rule).

```yaml
type: { kind: bytes, n: { kind: ref, field: length } }
type: { kind: bytes, n: { kind: remaining } }  # all remaining bytes in the enclosing scope
```

A `bytes` field may carry a `display` hint (§14) to tell display-layer tools
how to render the payload: `ascii`/`utf8` for text (an HTTP request line, SIP,
DNS labels), `addr` for a structured address (MAC, IPv6), or the default `hex`
for an opaque blob. This is **display-only** and carries no wire semantics
(`bytes` round-trips identically regardless).

> **Name-compression pointers (out of scope).** Name-compression pointers
> (DNS RFC 1035 §4.1.4, NBNS, mDNS) are representable at the wire level as a
> 2-byte pointer field, discriminated from a label by a `peek` on the leading
> two bits (value `11`) and reading the lower 14 bits as the offset. However,
> **dereferencing** that absolute offset to reconstruct the logical name —
> jumping to an arbitrary (usually backward) message offset and re-entering
> the parser to read a variable-length label sequence there — is **out of
> scope** for PSDL and is a codec/tool-layer concern. PSDL's position
> primitives are forward-only and relative (`peek` is non-consuming and
> bounded, `remaining`/`enclosingBits` give scope budgets not addressable
> locations, `align` only moves forward); there is no absolute-offset
> random-access primitive, and adding one would undermine the forward-only
> parse model the rest of the spec relies on. This parallels the §7
> delegation of protocol-linking resolution to the tool layer. See §16 for
> the consolidated rationale and the families of patterns this excludes.

> **Template-defined record layouts (out of scope).** Some protocols define a
> record's field layout in a Template Record that the Data Records reference at
> runtime. This template may arrive in a prior packet **or** ride in the *same*
> packet ahead of the data: IPFIX (RFC 7011) and NetFlow v9 (RFC 3954) commonly
> carry a Template FlowSet and the Data FlowSet it describes in one UDP packet,
> template ordered before data (RTPS/DDS is the same class). PSDL can parse the
> template (a `repeat` of `{ informationElementId, fieldLength }` entries) and
> can parse the data set as opaque `bytes`, but it **cannot** parse a data
> record *as* the fields the template defined — even fully intra-packet, with
> the template parsed earlier in the same body. The obstruction is
> **runtime-discovered field-layout instantiation**, not session/cross-packet
> state: the data record's layout (a list of widths of runtime-determined
> arity) is discovered by parsing the template, and no primitive turns those
> parsed `{ id, len }` pairs into the *structure* of a later region.
> `switch`/`lookup` discriminate a value to select among statically-declared
> arms, not to synthesize a field list; `repeat` can iterate the template
> entries and a `bounded` scope can wall off the data set as opaque bytes, but
> neither binds the parsed entries as the schema of the data region; recursive
> defs and `imports` shape only statically-declared structure. PSDL describes a
> single self-describing packet type, so template-defined dynamic record
> layouts are **out of scope** and are a codec/tool-layer concern — structurally
> the same class as DNS compression-pointer dereferencing above.

### `enum` — named enumeration

Keys are numeric values; values are labels (optionally with doc).

```yaml
type:
  kind: enum
  bits: 8
  variants:
    6:
      label: TCP
      doc: Transmission Control Protocol
    17:
      label: UDP
      doc: User Datagram Protocol
```

### `varint` — variable-length integer

`encoding` names a variable-length integer scheme. The values below are
predefined; **arbitrary strings are also accepted** for custom encodings
(the codec is responsible for implementing them, just as with
`checksumAlgorithm`). If a decoder encounters a `varint` field with an
encoding string it does not implement, this is a **runtime error**;
subsequent fields cannot be parsed. This is a harder failure than an unknown
`checksumAlgorithm` because the byte count consumed by the varint field is
also unknown, making the subsequent parse stream position indeterminate.

| Value | Description |
|-------|-------------|
| `quic` | QUIC variable-length integer (RFC 9000 §16) |
| `protobuf` | Protocol Buffers varint (base-128, little-endian groups) |
| `cbor` | CBOR unsigned integer (major type 0) |
| `ea-terminated` | Extension-bit: byte LSB=0 means more bytes follow, LSB=1 = last byte (Frame Relay DLCI, LAPD) |
| `leb128` | Unsigned LEB128 (WASM, DWARF) |

```yaml
type: { kind: varint, encoding: quic }
type: { kind: varint, encoding: ea-terminated }
type: { kind: varint, encoding: my-custom-scheme }
```

> **CoAP option delta/length:** CoAP uses a 4-bit base nibble with sentinel
> values 13, 14, 15 triggering 1- or 2-byte extensions. This pattern is not
> a simple EA-bit continuation; model it with a `switch` on the 4-bit nibble
> with `bytes` arms for each extended form.

### `berLength` — BER length field

Self-describing 1–N byte length as used in ASN.1/TLS. The optional `maxBytes`
property (1–5, default 5) constrains the maximum encoded length.
Declaring `maxBytes > 5` is a validation error.
Receiving a wire-encoded length that exceeds `maxBytes` is a runtime error.

```yaml
type: { kind: berLength }
type: { kind: berLength, maxBytes: 3 }
```

> **Indefinite-length (BER/CER 0x80).** `berLength` models the **definite**
> form only. The value it yields for the indefinite form (length octet
> `0x80`, content terminated by a two-byte `00 00` End-of-Contents marker) is
> **undefined**, and a `berLength` field MUST NOT be used as a `bytes.n` /
> `bounded.bytes` source there. Model the indefinite constructed form by
> composing existing primitives: `peek` the length byte, `switch` on `0x80`,
> and for the indefinite arm parse the contents with a `repeat` whose
> `count.until` is `peek(8) == 0` (a real BER tag is never `0x00` in content
> position; `0x00` begins the EOC) over the recursive value element, then
> consume the 2-byte EOC as a trailing fixed field. Do not use the definite
> `bounded`-scope idiom shown for ASN.1 in §6 for indefinite-length values.

---

## 4. Expressions

Expressions are pure, serialisable values used in field lengths, repeat counts,
switch discriminators, and optional conditions.

### Literal

```yaml
{ kind: lit, value: 20 }
```

An integer constant may also be written as a bare YAML integer wherever an
expression is expected:

```yaml
count: 4                           # equivalent to { kind: lit, value: 4 }
type: { kind: bytes, n: 0 }        # n: 0 is equivalent to n: { kind: lit, value: 0 }
```

### Field reference

Refers to a field's value by id. Only fields that appear **before** the current
container in document order are reachable in body expressions (see §10.1).
Expressions inside `constraints` are exempt and may reference any field.

```yaml
{ kind: ref, field: totalLength }
{ kind: ref, field: src.oct0 }   # ref-expanded field
```

A bare YAML string that is a valid field id may also be used as a shorthand:

```yaml
type: { kind: bytes, n: length }        # equivalent to n: { kind: ref, field: length }
count: recordCount                      # equivalent to { kind: ref, field: recordCount }
```

If the referenced field is **absent** from the wire (optional not taken,
switch arm not selected, ref not expanded), the expression yields the field's
seeded value per §10.2, or `0` if none.

A `ref` whose `field` is a **`repeat` container's `id`** (rather than a leaf
field) evaluates to that repeat's **completed iteration count**, reusing the
`env[repeat.id]` value mandated in §10.7 (which §10.7 requires the decoder to
populate for fixed-count repeats as well as `count: eos` repeats). This lets a
count field back-propagate via an ordinary constraint
(`countField == <repeatId>`) using the existing constraint solver (§9) — note
this returns the element count, not bytes; for the wire-byte footprint use
`wireSize` (below). Count fields whose value must equal the number of repeated
elements (IPv4 options, DNS qdcount/ancount/nscount, BGP path-attribute count,
TLV lists) are otherwise inexpressible when elements are variable-width, since
`wireSize` only back-solves a count when every element is fixed-width.

In body expressions, a `ref` to a repeat container's `id` is subject to the
§10.1 forward-reference rule exactly like a leaf `ref`: the repeat container
must precede the expression in document order. The seed-injected
`env[repeat.id]` (§10.7) makes the value available for constraints (which are
forward-exempt) and for body expressions placed **after** the repeat;
referencing a repeat id from a body expression that **precedes** the repeat in
document order is a validation error (§11.1).

### Binary operation

```yaml
{ kind: op, op: "+", a: { kind: ref, field: a }, b: { kind: lit, value: 8 } }
```

Available operators:

| Operator | Description | Notes |
|----------|-------------|-------|
| `+` `-` `*` `/` `%` | Arithmetic | `/` truncates toward zero; div/mod by zero = runtime error |
| `<<` `>>` | Shift | Arithmetic right shift; operates on 32-bit integers |
| `==` `!=` `<` `<=` `>` `>=` | Comparison | Result is `0` or `1` |
| `&` `\|` `^` | Bitwise AND / OR / XOR | Operates on 32-bit integers |

> **Note on 64-bit fields.** Bitwise and shift operators are evaluated as 32-bit
> integers. For fields wider than 32 bits, use arithmetic operators and `cond`
> instead of bit manipulation.

### Conditional (ternary)

Evaluates `t` if `test ≠ 0`, otherwise `f`.

```yaml
kind: cond
test: { kind: op, op: "==", a: { kind: ref, field: version }, b: { kind: lit, value: 4 } }
t: { kind: lit, value: 1 }
f: { kind: lit, value: 0 }
```

### Table lookup

Maps a key expression to a value using a discrete lookup table. Useful for
non-linear mappings that cannot be expressed as arithmetic, such as the CAN FD
DLC-to-byte-count table. If the key is not present in the table, the result
is `0` (silent).

**Key type rules:** Table keys are non-negative decimal integer literals.
Negative keys are not supported (use a `cond` expression to handle negative
discriminators before the lookup). The key expression result is truncated
toward zero to an integer before lookup (identical to the `/` operator rule).
If the truncated integer is negative, it will never match any table key (all
keys are non-negative) and the result is `0`, identical to the key-not-found
case. A YAML table key that is not a non-negative decimal integer is a
validation error.

**Value type rules:** Table values must be non-negative decimal integer
literals. A YAML table value that is not a non-negative decimal integer is
a validation error. Negative or non-integer values are not permitted because
lookup results feed into `bytes.n` and `repeat.count`, which require
non-negative integers. (See §11.1 for the corresponding validation error.)

```yaml
kind: lookup
key: { kind: ref, field: dlc }
table:
  0: 0
  1: 1
  # ...
  9: 12    # DLC 9 → 12 data bytes
  10: 16
  11: 20
  12: 24
  13: 32
  14: 48
  15: 64
```

### Peek

Reads `bits` bits from the stream at `offset` bits past the **current parse
position**, without consuming them. `offset` defaults to `0`.

```yaml
{ kind: peek, bits: 8 }                               # next byte
{ kind: peek, bits: 4, offset: { kind: lit, value: 4 } }
```

**Rules:**

- `peek` may only appear in `switch.on`, `optional.when`, and
  `repeat.count` (including the `until` sub-expression). Using it inside
  `bytes.n` or `encrypted.wireBits` is a validation error.
- The offset is relative to the **current parse position** at evaluation time.
  The exact definition of "current parse position" for each context is given in
  §10.6.
- If the peeked region extends beyond available data, the result is `0`.
- `peek` is the only expression form that may read data not yet parsed.

### Byte-bounded repeats

There is no dedicated "bits consumed so far" primitive and no repeat
byte-limit primitive. A repeat that must terminate after a given number of
bytes is expressed declaratively with a `bounded` scope wrapping the repeat
with `count: eos`. This idiom is described canonically in §5 (Bounded scope).

### Wire size of a named element (`wireSize`)

Returns the total **bytes** consumed on the wire by a named container or
field (`target`), including all recursively nested content for containers.
For a leaf field this is the field's wire footprint: for fixed-width types it
equals `bits / 8`; for `varint` and `berLength` fields the encoded size
varies. A field is the leaf case of a named element, so `wireSize` covers
both the per-field byte count and the whole-container byte count.

```yaml
{ kind: wireSize, target: avpData }    # total bytes of a bounded/recursive container
{ kind: wireSize, target: streamId }   # bytes of a single field (1/2/4/8 for a QUIC varint)
```

**Rules:**

- `wireSize` may appear in `constraints` expressions, in a `computedFrom`
  property on a `Field`, and in body expressions (the positions enumerated in
  §10.1) when its `target` precedes the expression in document order (the same
  forward-reference rule as `ref`).
- If the `target` is absent (optional not taken, switch arm not selected,
  ref not expanded) the result is `0`. For a field whose immediate parent is
  an `optional`, target the inner field's `id` (not the `optional`
  container's id); if that optional is absent the result is `0`.
- The bottom-up-vs-forward evaluation is determined by context, not by a
  separate primitive: in body expressions it is resolved forward as the
  target is parsed; in `constraints`/`computedFrom` it is evaluated
  **bottom-up** after recursive encoding of nested content is complete,
  allowing codec back-propagation to fill length fields in recursive
  structures.
- In a body expression the `target` must be a container or field that is
  fully parsed (closed) before the expression is evaluated — i.e. it precedes
  the expression in document order **and** is not an ancestor still open on
  the parse stack. A `wireSize` whose target is an enclosing/not-yet-closed
  container in a body expression is a validation error; use it only in
  `constraints`/`computedFrom` (bottom-up) for such targets.
- During DECODE, `wireSize: target` in a constraint or `computedFrom` resolves
  to the actual byte count consumed on the wire by the target during the Parse
  phase (§10.0); the bottom-up evaluation described above applies only during
  SERIALIZE, where nested content is encoded first and its size summed
  bottom-up to fill the field.

**`computedFrom` property on `Field`:**

A `Field` may carry an optional `computedFrom` property whose value is a
`wireSize` expression. This gives the codec explicit instruction to
compute and fill the field after recursive encoding is complete:

```yaml
- id: avpLength
  name: AVP Length
  type: { kind: int, bits: 24 }
  category: length
  computedFrom: { kind: wireSize, target: avpData }
```

A `computedFrom` annotation does not affect parsing (the wire value is
read normally); it is a serializer hint only. Using `computedFrom` with
any expression other than `wireSize` is a validation error.

### Previous iteration field reference (`prevIter`)

Available only within a `repeat.count.until` expression. References the value
of a named field from the **most recently completed** iteration of the
immediately enclosing repeat. Its sole purpose is expressing loop-termination
conditions that depend on the previous iteration.

```yaml
{ kind: prevIter, field: tsn }   # value of 'tsn' from the previous iteration
```

**Rules:**

- `prevIter` is valid only inside `repeat.count.until`.
- On the first iteration (no prior iteration exists), `prevIter.field`
  yields the field's seeded value per §10.2, or `0` if none.
- Using `prevIter` outside `repeat.count.until` is a validation error.

> **Cross-iteration invariants** (e.g. "SCTP DATA chunk TSNs must be strictly
> increasing") are **not** expressed in PSDL. There is no per-iteration
> assertion facility; such "check an expression, warn on mismatch" behavior
> is the job of §9 constraints (for fields reachable by id) or, for
> monotonicity and other genuinely cross-iteration checks the constraint model
> cannot reach, the codec layer — consistent with §6's delegation of non-length
> per-instance invariants to the codec. **Cumulative/accumulator
> reconstruction across iterations** (e.g. a CoAP option's absolute number =
> running sum of all prior option deltas) is likewise **out of scope** and a
> codec/tool-layer concern, for the same reason: `prevIter` exposes only the
> last iteration's value and there is no fold/accumulator primitive. This is a
> value-reconstruction gap, not a structural parse gap — each option's wire
> footprint still depends only on its own delta/length nibbles (the §3 CoAP
> switch idiom), so subsequent parsing is unaffected; only the absolute option
> number cannot be materialized as a `virtual` field.

### Remaining bytes (`remaining`)

A **scope-providing container** is one of exactly three containers that
establishes an independent wire-cursor budget: a `bounded` scope, an
`encrypted.plaintext` struct, or the top-level `body`. No other container
(`group`, a plain inline `struct`, `repeat`, a `switch` arm, `optional`)
provides a scope; `remaining`/`enclosingBits` and `count: eos` resolve against
the nearest enclosing scope-providing container.

The single primitive for 'bytes left in the immediately enclosing scope'. It
resolves to `(scope byte budget) − (bytes already consumed within that scope
at the point of evaluation)`, where the enclosing scope is the nearest
scope-providing container. It replaces the former `remainingBytes`,
`scopeRemainingBytes`, `enclosingBytes`, and `totalPacketBytes` primitives,
which all computed the same value differing only by scope kind.

```yaml
# Consume the remaining option bytes as a raw blob (mid-scope use is allowed)
type: { kind: bytes, n: { kind: remaining } }

# Consume all plaintext bytes except the last 2 (end-anchored fields follow)
type: { kind: bytes, n: { kind: op, op: "-", a: { kind: remaining }, b: { kind: lit, value: 2 } } }

# QUIC STREAM: use Length when LEN=1, otherwise consume all remaining bytes
n:
  kind: cond
  test: { kind: ref, field: lenBit }
  t: { kind: ref, field: length }
  f: { kind: remaining }
```

**Rules:**

- `remaining` is valid in `bytes.n` and any other body expression inside a
  scope-providing container. It may appear at any position regardless of how
  many data-consuming containers follow it — mid-scope, in last position, or
  inside a `cond`. (A **data-consuming** container is one that advances the
  wire cursor: a `Field` with a non-zero-width type, a `bytes` field, a
  `repeat`, a `bounded` scope, an `encrypted` region, a selected `switch` arm,
  or `align` padding; a `virtual` field and a non-selected switch arm consume
  nothing.)
- Outside any scope-providing container there is no defined budget; using
  `remaining` there is a validation error.
- The top-level `body`'s scope budget is the **decoder-injected total packet
  byte count**. `remaining` in a top-level `body` expression therefore
  requires that the decoder inject the total packet size (e.g. from the link
  layer); when no total is injected (a raw buffer parsed with no externally
  supplied length), `remaining` at the top-level body has no defined budget
  and is a **runtime error** (the parse stream position cannot be bounded). A
  `bounded` scope and an `encrypted.plaintext` region always have a defined
  budget (the bounded `bytes` expression and the `wireBits` budget
  respectively), so `remaining` is always meaningful inside those.
- The 'absolute budget' of a scope is `(bytes already consumed) + remaining`;
  where an absolute byte total is genuinely needed, reference the relevant
  length field directly. For bit-precision needs use `enclosingBits` below.
- **Sub-byte rounding.** `bytes already consumed` is measured as
  `ceil(bits consumed in scope / 8)` — a partially-consumed byte counts as
  fully consumed (matching the `align` round-up rule in §5). Consequently
  `remaining` is only well-defined for sizing a `bytes` field when the cursor
  is byte-aligned; using `remaining` to size data while mid-byte is a
  **runtime error**. Size a final `bytes` field only after a byte boundary
  (insert an `align` first if a preceding sub-byte field left the cursor
  mid-byte), or use `enclosingBits` arithmetic for sub-byte regions.

  Worked example: a 4-byte `bounded` scope (`remaining` = 4 at entry)
  containing a 12-bit `bits` field, then `align to: 16`, then a `count: eos`
  repeat. The `bits` field leaves the cursor at bit 12 (mid-byte); `align`
  first rounds 12 up to 16 bits (`bytePosition = ceil(12/8) = 2`, which is
  already a multiple of `16/8 = 2`, so 0 further padding bytes), charging the
  round-up so 2 bytes of the budget are now consumed. The `count: eos` repeat
  then parses within the remaining `4 - 2 = 2` bytes. Evaluating `remaining`
  *before* the `align`, while the cursor sits at bit 12, would be a runtime
  error (mid-byte).

### Scope bit budget (`enclosingBits`)

The single primitive for the **injected absolute bit budget of the nearest
scope-providing container that carries one**. It mirrors `remaining`, but
returns the scope's total bit budget rather than the bytes left in it. The two
scope-providing containers that carry an injected bit budget are:

- an `encrypted.plaintext` struct — `enclosingBits` equals the result of the
  enclosing `encrypted` container's `wireBits` expression, evaluated when the
  encrypted container is entered during parse; and
- the **top-level `body`** — `enclosingBits` is the externally decoder-injected
  total packet bit count (e.g. from the link layer).

(A `bounded` scope's budget is authored in bytes, not injected in bits, so it
does not provide `enclosingBits`.) The two cases differ in their evaluation
phase and forward-reference treatment (see §10.1): at the top-level `body`,
`enclosingBits` is a decoder-injected constant available before parsing and is
**exempt** from the forward-reference restriction; inside an
`encrypted.plaintext` it is computed from the enclosing `wireBits` expression
during parse and is **subject** to the normal forward-reference rule (the
fields backing `wireBits` must precede the `encrypted` container). It merges
the former per-scope bit-budget primitives (the encrypted-scope budget and
`totalPacketBits`) into a single `enclosingBits`, which computed the same bit
budget differing only by scope kind. Authors write `enclosingBits / 8`
for a byte boundary.

```yaml
# Byte boundary derived from the bit budget (sub-byte-aware), in an
# encrypted.plaintext struct or the top-level body
type: { kind: bytes, n: { kind: op, op: "/", a: { kind: enclosingBits }, b: { kind: lit, value: 8 } } }
```

**Rules:**

- `enclosingBits` is valid only inside an `encrypted.plaintext` struct or the
  top-level `body`. Using it outside a scope-providing container that carries
  a bit budget (e.g. inside a `bounded` scope or a nested non-scope
  `struct`) is a validation error.
- At the top-level `body`, `enclosingBits` is a decoder-injected constant and
  requires the decoder to inject the total packet size; when no total is
  injected it has no defined budget (same injection requirement as `remaining`
  at the top-level body), and it is exempt from the forward-reference rule.
- Inside an `encrypted.plaintext`, `enclosingBits` equals the enclosing
  `encrypted` container's `wireBits` and is subject to the forward-reference
  rule (§10.1): every field referenced by that `wireBits` expression must
  precede the `encrypted` container in document order. If the `encrypted`
  container omits `wireBits`, the plaintext has no defined bit budget and
  `enclosingBits` there is a validation error (§5 Encrypted, §11.1).
- It is useful when the bit-precise size is not stored in any field of the
  packet being authored. When a length field does exist, prefer referencing it
  directly. For byte-aligned totals, prefer `remaining`.

### Cross-layer field reference (`enclosingField`)

References a named field from the immediately enclosing protocol layer's
parsed state.

```yaml
{ kind: enclosingField, field: protocolType }
```

`enclosingField` is valid in `constraints` **only**; using it in any body
expression is a validation error (§11.1). It reads from a separate
enclosing-layer env supplied by the codec and yields `0` when no enclosing
layer is present. See §7 (Cross-layer field access) for the full semantics
and §10.0 for the phase in which the enclosing-layer env is available.

---

## 5. Containers

### Field

The fundamental unit. `kind` may be omitted.

```yaml
- id: srcPort
  name: Source Port
  type: { kind: int, bits: 16 }
  category: addressing
  doc: Sender's port number
  byteOrder: BE
  display: dec
  meta:
    rfc: 793
    section: "3.1"
```

Full property reference:

| Property | Required | Description |
|----------|----------|-------------|
| `id` | yes | Identifier used in expressions |
| `name` | yes | Human-readable label |
| `type` | yes | Wire type |
| `kind` | no | Must be `"field"` if present |
| `doc` | no | Description string |
| `meta` | no | Per-field RFC annotation `{ rfc?, section? }` |
| `category` | no | Semantic category token (see §5.1) |
| `const` | no | Value this field must equal; see §5.2 |
| `defaultValue` | no | Env seed value when field is absent |
| `byteOrder` | no | Per-field byte order override (`int`/`enum` only) |
| `display` | no | Display hint: numeric `hex`, `dec`, `oct`, `bin` (default `dec`); for `bytes` fields also `ascii`, `utf8`, `addr` (default `hex`). Display-only (see §14) |
| `next` | no | Protocol-linking map (see §7) |
| `checksumAlgorithm` | no | Checksum algorithm (see §8) |
| `checksumCovers` | no | Fields covered by this checksum (see §8) |
| `checksumPseudoHeader` | no | Well-known pseudo-header to prepend (see §8) |
| `checksumParams` | no | CRC algorithm parameters (see §8) |

#### 5.1 Category tokens

| Token | Meaning |
|-------|---------|
| `addressing` | Source or destination address |
| `identifier` | Version, type, protocol number |
| `length` | Length or size field |
| `type` | Type / kind discriminator |
| `flags` | Boolean flag bits |
| `reserved` | Must-be-zero / future use |
| `checksum` | Integrity check value |
| `variable` | Payload or generic variable data |
| `payload-marker` | Marks the start of the upper-layer payload |

#### 5.2 `const`

Declares that this field must carry a fixed value. A mismatch is a runtime
error during parsing. `const` also sets the env seed for this field (see §10.2);
if `defaultValue` is also present, `const` takes priority over `defaultValue`
for seeding purposes.

```yaml
- id: version
  name: Version
  type: { kind: int, bits: 4 }
  const: 4
  category: identifier
```

### Ref (struct instantiation)

A `ref` container instantiates a `defs` struct in the `body`. It is one of the
body container kinds the parser dispatches on (alongside field, group,
optional, repeat, switch, align, bounded, and encrypted).

```yaml
- kind: ref
  ref: ipv4Addr
  id: src
  name: Source Address
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"ref"` |
| `ref` | yes | Target def name (local `defs` key or import-qualified, §1.2) |
| `id` | yes | Instantiation id; becomes the prefix of the expanded field ids |
| `name` | no | Human-readable label |

See §6 for expansion rules (transparent scope inheritance, the
`{ref.id}.{field.id}` and repeat-indexed `{ref.id}.{field.id}#N` id forms).

### Virtual field

A computed auxiliary field that consumes **no wire bytes**. Its `expr` is
evaluated at parse time using the same forward-reference rules as body
expressions (§10.1), and its `id` is added to the env and may be referenced
by subsequent body expressions, `constraints`, and `checksumCovers`.

```yaml
- kind: virtual
  id: offBit
  expr:
    kind: op
    op: "&"
    a: { kind: op, op: ">>", a: { kind: ref, field: type }, b: { kind: lit, value: 2 } }
    b: { kind: lit, value: 1 }
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"virtual"` |
| `id` | yes | Identifier used in subsequent expressions |
| `expr` | yes | Expression evaluated at parse time |
| `name` | no | Human-readable label |
| `doc` | no | Description |

**Rules:**

- A `virtual` field occupies zero wire bits. It does not advance the
  parse position.
- Its `expr` follows the same forward-reference rule as other body
  expressions: only fields that appear before the `virtual` field in
  document order are reachable.
- A `virtual` field id may be used in `checksumCovers` but contributes
  zero bytes to checksum input (it is display-only metadata in that
  context; prefer listing the underlying source field instead).
- `virtual` fields are not permitted inside `defs` (recursive contexts
  may cause evaluation ordering issues); placing one inside a def is a
  validation error.

### Group

Collapses adjacent fields into one visual row. `doc` is used by LSP for hover
documentation. `meta` enables per-group RFC annotation (e.g. for Chrome extension
field-level deep-linking).

```yaml
- kind: group
  id: flags
  name: Flags
  doc: TCP control bits (RFC 793 §3.1)
  meta:
    rfc: 793
    section: "3.1"
  children:
    - id: syn
      name: SYN
      type: { kind: bits, n: 1 }
    - id: ack
      name: ACK
      type: { kind: bits, n: 1 }
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"group"` |
| `id` | yes | Group identifier |
| `name` | yes | Human-readable label |
| `children` | yes | Ordered list of containers |
| `doc` | no | Description for LSP hover |
| `meta` | no | Per-group RFC annotation `{ rfc?, section? }` |
| `category` | no | Semantic category (same tokens as Field) |

### Optional

Conditionally includes a container. `when` is evaluated as a boolean:
`0` = absent, non-zero = present.

An `optional` **may** be nested inside another `optional`. The inner `when`
expression is evaluated **only if the outer optional is present**
(short-circuit semantics). If the outer optional is absent, the inner
container is also treated as absent without evaluating the inner `when`.
This extends to arbitrary nesting depth. See §10.8.

When a container is absent, all its fields yield their seeded value per §10.2
when referenced by subsequent expressions.

```yaml
- kind: optional
  when: { kind: ref, field: hasOptions }
  container:
    kind: group
    id: tcpOptions
    name: TCP Options
    children:
      - id: kind
        name: Kind
        type: { kind: int, bits: 8 }
      - kind: optional
        when: { kind: op, op: "==", a: { kind: ref, field: kind }, b: { kind: lit, value: 8 } }
        container:
          id: timestamp
          name: Timestamp
          type: { kind: int, bits: 32 }
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"optional"` |
| `when` | yes | Boolean expression (`0` = absent, non-zero = present) |
| `container` | yes | The container conditionally included |
| `id` | no | Optional identifier. Assigns the container to a `rendererHints.sections` entry (§13) and may be the `target` of a `wireSize` (§4). For `wireSize`, target the inner field's `id` rather than the optional's `id`; an absent optional yields `0` |
| `doc` | no | Description for LSP hover |
| `meta` | no | RFC annotation `{ rfc?, section? }` for per-region deep-linking |

### Repeat

Repeats a struct element.

```yaml
# Fixed count
- kind: repeat
  id: records
  count: { kind: ref, field: recordCount }
  element:
    id: record
    fields:
      - id: type
        name: Type
        type: { kind: int, bits: 8 }

# Until end of stream
# The decoder sets env[repeat.id] = actual iteration count before normalization.
- kind: repeat
  id: entries
  count: eos
  element:
    id: entry
    fields:
      - id: value
        name: Value
        type: { kind: int, bits: 32 }

# Until sentinel: stop once a field equals 0
- kind: repeat
  id: labels
  count:
    until:
      kind: op
      op: "=="
      a: { kind: ref, field: labelLen }
      b: { kind: lit, value: 0 }
  element:
    id: label
    fields:
      - id: labelLen
        name: Length
        type: { kind: int, bits: 8 }
      - id: labelStr
        name: Label
        type: { kind: bytes, n: { kind: ref, field: labelLen } }

# Until N bytes consumed: wrap the repeat in a bounded scope with count: eos.
# See §5 (Bounded scope) for the canonical byte-bounded example.
```

**Repeat scoping:**
Inside a repeat element, expressions may reference fields that appear before
the current field within the **same iteration** only. Fields from previous
iterations are not reachable via `ref` (except via `prevIter`, §4). The
`until` expression is evaluated after each element has been fully parsed and
may reference any field in the current iteration. For byte-bounded iteration,
wrap the repeat in a `bounded` scope with `count: eos` (see §5 Bounded scope).

The repeat `element` is an inline struct following the §6 Struct shape
(`{ id, fields }`) and may therefore also carry `doc` (for LSP hover) and
`meta { rfc?, section? }` (for per-region RFC deep-linking).

**`eos` repeat:** End-of-stream detection is decoder-specific. During the
**seed** phase (§10.0), the decoder **MUST** inject the iteration count into
`env[repeat.id]`. If the key is absent, the normalize phase defaults to `0`
iterations.

### Switch

Selects one struct arm based on a discriminator expression.

**Case key formats:**

| Format | Example | Meaning |
|--------|---------|---------|
| Decimal string | `"6"` | Exact value match |
| Range | `"0-127"` | Inclusive range (both ends) |
| List | `"6,17,58"` | Multiple exact values → same arm |
| Default | `"_"` | Catch-all for unmatched values |

**Key evaluation order:** For a given discriminator value, keys are tested in
this order: (1) exact match, (2) list membership, (3) range containment,
(4) `"_"`. The first matching key wins. When multiple range keys could match,
the **first** matching range key in document order wins.

The discriminator value is truncated toward zero to an integer before matching
(identical to the `/` operator and `lookup` key rule). If no key matches
(including a negative value that matches no key and no `_`), the switch consumes
zero bytes per the empty-struct rule below. Range and list keys are
non-negative decimal integers; a negative-valued bound is a validation error.

```yaml
- kind: switch
  id: payload
  on: { kind: ref, field: protocol }
  cases:
    "6":
      id: tcp
      fields:
        - id: srcPort
          name: Source Port
          type: { kind: int, bits: 16 }
    "17,136":
      id: udp
      fields:
        - id: srcPort
          name: Source Port
          type: { kind: int, bits: 16 }
    "0-9":
      id: raw09
      fields:
        - id: data
          name: Data
          type: { kind: bytes, n: { kind: ref, field: totalLength } }
    _:
      id: unknown
      fields:
        - id: data
          name: Data
          type: { kind: bytes, n: { kind: ref, field: totalLength } }
```

> **Note:** The `_` key must appear inside the `cases` map, not as a sibling
> property. The JSON Schema does not define a separate `default` property.

**Non-selected arms:** Fields in non-selected arms are not added to the env.
Referencing them in subsequent body expressions yields their seeded value per
§10.2, or `0`. Constraints referencing non-selected-arm fields are silently
skipped.

If the discriminator value matches no case key and no `_` default is defined,
the switch consumes zero bytes (equivalent to an empty struct). This is
not an error.

Each case arm is an inline struct following the §6 Struct shape (`{ id,
fields }`) and may therefore also carry `doc` (for LSP hover) and
`meta { rfc?, section? }` (for per-region RFC deep-linking).

### Alignment padding (`align`)

Consumes zero or more bytes to align the current parse position to a given
bit boundary. No `id` is required (the container contributes no named field
to the env).

```yaml
- kind: align
  to: 32     # consume 0–3 padding bytes to align to the next 4-byte boundary
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"align"` |
| `to` | yes | Alignment target in **bits** (must be a positive integer power of 2 **and a multiple of 8**, i.e. 8, 16, 32, 64, …) |
| `fill` | no | Byte value (0–255) used to fill padding bytes during serialization (default: unspecified / decoder-defined) |
| `id` | no | Optional identifier if the padding bytes need to be referenced |
| `doc` | no | Description |

**Rules:**

- The alignment reference point is the **absolute origin of the wire/packet
  byte stream** (the first bit of the top-level packet). `position` below is
  the parse position measured in bits from that absolute origin. Using the
  absolute origin — rather than the start of the enclosing scope — guarantees
  that `align` lands on a true wire boundary even when the enclosing
  scope-providing container does not itself begin on a multiple of `to`
  (e.g. a Grouped-AVP `bounded` scope that starts at an arbitrary offset).
  This matches the wire-absolute padding intent of SCTP/Diameter chunk
  alignment (§8).
- `to` is restricted to multiples of 8, but a preceding sub-byte `bits` field
  (or bit-width `int`/`enum`, §3), or a wide `bits` field read as a raw
  MSB-first bit run (§12), may leave the cursor mid-byte. An `align`
  therefore **first rounds the current bit position up to the next whole
  byte**, then advances to the `to` boundary. This round-up is defined on the
  raw bit position and involves no byte-order swap. Define `bytePosition =
  ceil(position / 8)` (the byte offset after rounding any partial byte up).
  If `bytePosition` is already a multiple of `to/8`, zero further padding
  bytes are consumed; otherwise the padding byte count consumed equals
  `(to/8 - (bytePosition % (to/8))) % (to/8)`. The total bytes consumed by the
  `align` includes the partial-byte round-up: the cursor ends on a multiple of
  `to` bits from the absolute origin.
- **Inside a `bounded` scope**, the padding bytes consumed by an `align`
  **are charged against the scope's byte budget** — they advance the scope
  cursor exactly like data bytes — even though the boundary they target is
  measured from the absolute wire origin, not from the scope start. A
  following `count: eos` repeat or `remaining` therefore sees those padding
  bytes as consumed. If the computed padding would exceed the scope's
  remaining byte budget, the `align` is a **runtime error**.

  Worked example: a `bounded` scope of 10 bytes that begins at absolute byte
  offset 6 contains a 1-byte field (cursor now at absolute offset 7,
  1 byte of the 10-byte budget consumed) followed by `align to: 32`. The
  next 4-byte boundary from the absolute origin is offset 8, so the align
  consumes `(4 - (7 % 4)) % 4 = 1` padding byte. That 1 byte is charged
  against the scope budget, leaving 8 of the 10 bytes; a subsequent
  `count: eos` repeat parses within those remaining 8 bytes.
- At the top-level `body` (or any scope), if the computed padding would run
  past the injected end-of-data, the `align` consumes only the bytes actually
  available and does **not** error — it caps at the scope/packet end. This
  covers e.g. SCTP chunk framing (RFC 4960 §3.2), where every chunk is padded
  to a 4-byte boundary except the last chunk of a packet, whose trailing
  padding MAY be omitted: at the final iteration the cursor may already sit at
  the injected end with fewer than the rounded-up padding bytes present, and
  the `align` simply consumes what remains. (Contrast the inside-a-`bounded`-
  scope rule above, where padding exceeding the declared byte budget is a
  runtime error: a `bounded` scope's budget is authored, not an injected
  end-of-data.)
- Alignment padding bytes are **excluded** from any enclosing checksum coverage
  unless the `align` container's `id` is explicitly listed in `checksumCovers`.
- `to` must be a positive integer power of 2 that is a multiple of 8; any
  other value is a validation error.
- `fill` specifies the byte value written to padding bytes during serialization.
  When absent, the fill value is decoder/encoder-defined. When present it also
  instructs the decoder to validate that incoming padding bytes equal `fill`;
  a mismatch is a validation warning (consistent with constraint-mismatch
  behavior in §11.3). `fill` must be an integer in the range 0–255; any other
  value is a validation error.
  Example: `{ kind: align, to: 32, fill: 0x00 }` (SCTP / Diameter zero-fill).

### Bounded scope

Constrains parsing of its contents to a declared byte count derived from an
expression. This creates a sub-stream cursor so that `count: eos` inside a
recursive def (or any nested context) terminates at the scope boundary rather
than at the end of the packet. It is the mechanism for parsing length-delimited
lists of repeated structures — e.g. Diameter Grouped AVPs, 802.11 sub-IEs.

This is the **canonical byte-bounded repeat** idiom: a `bounded` scope wrapping
a `repeat` with `count: eos` is the single, orthogonal way to terminate a
repeat after a given number of bytes (there is no dedicated repeat byte-limit
primitive). If a 'consumed-so-far in current scope' value is needed in an
expression, derive it as (scope budget − `{ kind: remaining }`) rather than
maintaining a separate per-repeat accumulator.

```yaml
- kind: bounded
  id: avpData
  bytes: { kind: op, op: "-", a: { kind: ref, field: avpLength }, b: { kind: lit, value: 8 } }
  fields:
    - kind: repeat
      id: containedAvps
      count: eos        # terminates at the bounded scope boundary, not end-of-packet
      element:
        id: avp
        fields:
          - id: avpCode
            name: AVP Code
            type: { kind: int, bits: 32 }
```

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"bounded"` |
| `id` | yes | Scope identifier |
| `bytes` | yes | Expression giving the byte count of this scope |
| `fields` | yes | Ordered list of containers parsed within the scope |
| `name` | no | Human-readable label |
| `doc` | no | Description |

**Rules:**

- `bytes` is evaluated using the same forward-reference rules as other body
  expressions (§10.1).
- Inside a `bounded` scope, `count: eos` on a `repeat` terminates when the
  scope's byte budget is exhausted. More generally, a `count: eos` repeat
  terminates at the boundary of its nearest enclosing scope-providing
  container — a `bounded` scope, an `encrypted.plaintext` struct (its
  `wireBits` budget), or the top-level `body` — not only a `bounded` scope.
  This is the same scope-provider list used by `remaining`/`enclosingBits`
  (§4); a frame list filling a decrypted payload (e.g. QUIC frames inside the
  protected payload, RFC 9000 §12.4) is therefore a `count: eos` repeat
  directly inside the `encrypted.plaintext`, with no field-backed length to
  wrap in a `bounded` scope.
- The `remaining` primitive (§4) resolves against the **immediately
  enclosing** bounded scope. `bounded` scopes may be nested; each provides an
  independent budget, so `remaining` inside a nested scope consumes only that
  inner scope's remaining bytes, not any outer scope or the top-level body.
- A `bounded` scope inside a `recursive: true` def correctly confines `eos`
  repeats to the scope boundary at each recursive call site.

### Encrypted

Marks a region as encrypted.

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"encrypted"` |
| `id` | yes | Identifier for the encrypted container |
| `plaintext` | yes | Struct describing the decrypted content |
| `wireBits` | no | Expression for the encrypted region size in bits |
| `contextNote` | no | Human-readable note shown in the encrypted-region tooltip |
| `headerProtected` | no | Field ids within plaintext that are also header-protected |
| `name` | no | Human-readable label |
| `category` | no | Semantic category token |
| `doc` | no | Description |

```yaml
- kind: encrypted
  id: tlsRecord
  contextNote: Encrypted with negotiated cipher suite
  plaintext:
    id: tlsPlaintext
    fields:
      - id: contentType
        name: Content Type
        type: { kind: int, bits: 8 }
        category: identifier
      - id: data
        name: Application Data
        type: { kind: bytes, n: { kind: ref, field: length } }
  wireBits:
    kind: op
    op: "*"
    a: { kind: ref, field: length }
    b: { kind: lit, value: 8 }
  headerProtected: [contentType]
```

When `wireBits` is absent, the `encrypted.plaintext` struct has **no defined
byte budget**: `remaining` and `enclosingBits` inside that plaintext have no
defined value and using them is a validation error (§11.1), paralleling the
top-level `body` 'no injected size' rule (§4). Provide `wireBits` whenever the
plaintext contains budget-dependent expressions.

#### End-anchored fields

Some protocols place type- or length-discriminating fields at a **fixed offset
from the end** of a variable-length region (IPsec ESP Pad Length / Next Header).
PSDL has no dedicated end-anchoring container: model these as ordinary
fixed-width fields placed **after** a `bytes` field sized
`remaining - <constByteCount>`, where `<constByteCount>` is the total size of
the end-anchored fields. The data field consumes everything except those
trailing bytes, and the trailing fixed-width fields then parse normally in
order, ending exactly at the region boundary. This idiom works only when the
trailing fields sit at a **fixed** distance from the end **and** no trailing
field's value determines the size of a field that precedes it (the back-off
distance `<constByteCount>` must be a compile-time constant, not a wire
value). See the TLS 1.3 and RTP/SRTP notes below for the two out-of-scope
end-anchoring cases this excludes.

```yaml
# IPsec ESP: last 2 bytes of decrypted payload (Pad Length, Next Header)
- kind: encrypted
  id: espPayload
  contextNote: Encrypted with negotiated ESP cipher
  wireBits: { kind: op, op: "*", a: payloadLen, b: { kind: lit, value: 8 } }
  plaintext:
    id: espPlaintext
    fields:
      - id: data
        name: Payload Data
        # consume everything except the trailing 2 bytes
        type: { kind: bytes, n: { kind: op, op: "-", a: { kind: remaining }, b: { kind: lit, value: 2 } } }
      - id: padLength
        name: Pad Length
        type: { kind: int, bits: 8 }
      - id: nextHeader
        name: Next Header
        type: { kind: int, bits: 8 }
        category: identifier
```

> **TLS 1.3 inner-plaintext content type (out of scope).** TLS 1.3
> (RFC 8446 §5.4) appends an arbitrary run of zero padding **after** the real
> content, and the inner `ContentType` is the **last non-zero byte**, not the
> byte at a fixed offset from the end. Locating it requires scanning backward
> from the end of the region skipping zero bytes — a backward, data-dependent
> search. PSDL's position primitives are forward-only and relative:
> `remaining`/`enclosingBits` give only a budget, not the location of the last
> non-zero byte; `peek` is forward and bounded; there is no reverse iteration
> and no 'scan until non-zero from end' construct, and a forward `repeat`
> cannot tell mid-stream whether a zero byte is trailing padding or real data
> without already knowing where the end content sits. The `remaining -
> <const>` idiom above only works when the trailing offset is fixed, which is
> **not** the TLS 1.3 case (it holds only when padding length is zero).
> Reconstructing the TLS 1.3 inner content type is therefore **out of scope**
> for PSDL — a codec/tool-layer concern — for the same forward-only reason
> DNS name-compression-pointer dereferencing (§3) is out of scope. Adding a
> backward-scan primitive would undermine the forward-only parse model the
> rest of the spec relies on.

> **RTP/SRTP padding (out of scope).** RTP (RFC 3550 §5.1) with the P bit set
> appends padding whose **last octet is a padding count** (including itself);
> the payload occupies `remaining - paddingCount` bytes, then `paddingCount-1`
> padding bytes, then the count octet. Unlike the TLS 1.3 case above (a
> backward *scan* for the last non-zero byte), here the end-anchored octet sits
> at a **fixed** offset from the end (1 byte) — but its **value sizes the
> preceding payload field**, and that value is only readable *after* the
> payload in forward parse order. This is a **data-dependent** back-off
> distance, distinct from the **fixed-constant** back-off the `remaining -
> <constByteCount>` idiom requires: writing `remaining - paddingCount` would
> reference the count octet before it is parsed (a forward-reference violation,
> §10.1/§10.4); `peek` cannot size the payload (it is restricted to
> `switch.on`/`optional.when`/`repeat.count`, not `bytes.n`, §11.1, and is
> forward-relative, not end-relative); and `remaining`/`enclosingBits` yield
> only a budget, never the value or location of the trailing octet. There is no
> reverse iteration, fold/accumulator, or end-relative addressing primitive.
> Reconstructing the RTP/SRTP payload boundary is therefore **out of scope** —
> a codec/tool-layer concern — for the same forward-only reason as the TLS 1.3
> inner-content-type note above and DNS compression-pointer dereferencing (§3);
> adding end-relative/backward addressing would undermine the forward-only
> parse model the rest of the spec relies on. §16.1 lists this as a member of
> the end-relative/backward-reference family and §16.3 records the bounded
> backward-window extension that would cover it in a future revision.

The end-anchored fields are ordinary fields: they are reachable in subsequent
`constraints` (e.g. `padLength` can appear in a constraint verifying data
alignment) and require the enclosing region to be byte-aligned (the
`remaining - <const>` data size is expressed in whole bytes). For a sub-byte
region, consume bits explicitly with `bits`/`bytes` fields and `enclosingBits`
arithmetic instead.

---

## 6. Struct definitions and reuse

```yaml
defs:
  ipv4Addr:
    id: ipv4Addr
    doc: 32-bit IPv4 address stored as four consecutive octets
    fields:
      - id: oct0
        name: Octet 0
        type: { kind: int, bits: 8 }
      - id: oct1
        name: Octet 1
        type: { kind: int, bits: 8 }
      - id: oct2
        name: Octet 2
        type: { kind: int, bits: 8 }
      - id: oct3
        name: Octet 3
        type: { kind: int, bits: 8 }

body:
  - kind: ref
    ref: ipv4Addr
    id: src
    name: Source Address
  - kind: ref
    ref: ipv4Addr
    id: dst
    name: Destination Address
```

Expanded ids: `src.oct0`, `src.oct1`, …, `dst.oct0`, …

These virtual ids can be used in expressions, `checksumCovers`, and `next`
target field references.

**Struct properties:**

| Property | Required | Description |
|----------|----------|-------------|
| `id` | yes | Struct identifier (must match the key in `defs`) |
| `fields` | yes | Ordered list of containers |
| `doc` | no | Description for LSP hover and tooling |
| `recursive` | no | `true` enables self-referential structs (see below) |

**Rules:**

- Field ids within a `def` must not contain `.`.
- Referring to a non-existent `defs` key is a validation error.
- Circular references (direct or indirect) within `defs` are forbidden
  **unless** the referenced struct has `recursive: true`.
- `defaultValue` on fields inside a `def` is honoured.
- `const` on fields inside a `def` is enforced for every expanded instance.
- A `ref` is a **transparent expansion**: it inherits surrounding scope
  (group membership, repeat index, etc.).
- In a `repeat` element, the expanded field ids carry both the ref prefix
  and the repeat index: `{ref.id}.{field.id}#N` (e.g. `src.oct0#2`).
- Scope ordering: expanded fields are visible from the position of the `ref`
  container in document order.
- Constraints are document-level only and cannot be scoped to a single `def`
  instantiation. To express per-instantiation invariants, add them as
  document-level constraints referencing the expanded instantiation ids.

### Recursive defs

When a `def` has `recursive: true`, it may contain `ref` containers pointing
to itself (directly) or to another `recursive: true` def (transitive recursive
link through recursive defs only). The decoder is responsible for enforcing a
reasonable depth limit; the PSDL validator does not impose one.

```yaml
defs:
  asn1Value:
    id: asn1Value
    recursive: true
    doc: ASN.1 BER-encoded value (tag-length-content)
    fields:
      - id: tag
        name: Tag
        type: { kind: int, bits: 8 }
      - id: len
        name: Length
        type: { kind: berLength }
      - kind: switch
        id: content
        on: { kind: ref, field: tag }
        cases:
          "48":                         # SEQUENCE (0x30)
            id: sequence
            fields:
              - kind: repeat
                id: children
                count: eos
                element:
                  id: item
                  fields:
                    - kind: ref
                      ref: asn1Value    # recursive self-reference
                      id: child
                      name: Child Value
          _:
            id: primitive
            fields:
              - id: value
                name: Value
                type: { kind: bytes, n: { kind: ref, field: len } }
```

**Limitations:**

- Recursive defs are not supported within constraint back-propagation (§9).
  The constraint solver treats recursive boundaries as unresolvable unknown
  values.
- A document-level constraint whose `lhs` or `rhs` references any field that
  is inside a recursive def expansion (e.g. `child.tag` in the example above)
  is **always silently skipped** during both constraint evaluation and
  back-propagation. It is not a hard validation error, but tools SHOULD emit
  a lint warning at load time to alert the author that the constraint will
  never be evaluated. This rule is consistent with §9 (constraint skipped when
  any referenced field is absent).
- Constraints are document-level only and cannot be scoped to a single def
  instantiation. To express per-instantiation invariants, add them as
  document-level constraints referencing the expanded instantiation ids.
- **Per-instance length invariants** (e.g. Diameter AVP-Length must equal
  the total wire size of that AVP) cannot be expressed as ordinary PSDL
  constraints for recursive defs. The `bounded` scope enforces the length
  at parse time by limiting the byte budget, which is the recommended
  mechanism. For serialization, use the `computedFrom: { kind: wireSize,
  target: id }` annotation on the length field (§4 wireSize); this gives
  the codec explicit instruction to compute and fill the field after
  recursive encoding is complete using a bottom-up pass. Without this
  annotation, a codec must compute length values procedurally.
- Whether an `encrypted` container is permitted inside a recursive def: each
  call-site expansion creates a fresh encrypted region and `remaining`/
  `enclosingBits` inside each `plaintext` scope to that call-site's
  `wireBits`, which is well-defined. `encrypted` containers are therefore
  **permitted** inside recursive defs.

**Limitations and workarounds:**

The following constraint types are always unsatisfiable for recursive defs
and must be checked procedurally in the codec:

1. **Non-length per-instance invariants** (e.g. a tag-value consistency rule
   across recursion levels) — `bounded` scopes cover only length invariants;
   all other per-instance checks must be delegated to the codec layer.
2. **Back-propagated length fields** — use `computedFrom: { kind: wireSize,
   target: id }` on the length field (§4 wireSize) to instruct the codec
   to compute the field bottom-up after recursive encoding; without it, the
   codec must compute these values procedurally.
3. **Any constraint whose `lhs` or `rhs` references a field inside a
   recursive def expansion** — always silently skipped (§9). Tools emit a
   lint warning. This rule applies transitively: a non-recursive def
   instantiated inside a recursive def shares the same constraint-skip
   behavior for those specific field references, because the constraint
   solver cannot resolve the recursive boundary regardless of whether the
   innermost def is itself marked `recursive: true`.

---

## 7. Protocol linking

```yaml
- id: protocol
  name: Protocol
  type: { kind: int, bits: 8 }
  category: identifier
  next:
    1:  icmp
    6:  tcp
    17: udp
    58: icmpv6
    _:  raw
```

**Naming convention:** Values in the `next` map SHOULD match the `name` or
one of the `meta.aliases` of the target PSDL document as found in the tool's
active packet registry. The registry may be `@packet-schema/presets`, a
user-supplied set of PSDL files, or a combination. Cross-registry name
collisions are resolved by the tool layer (e.g. by namespace prefix or
explicit override); PSDL does not define a conflict-resolution policy.

The `_` key is valid in `next` maps and means 'unconditionally link to this
protocol regardless of the field value'. It is the canonical way to model a
payload that is always the same protocol regardless of any discriminator.
Example (VXLAN inner Ethernet frame, RFC 7348):

```yaml
- id: vni
  name: VNI
  type: { kind: int, bits: 24 }
- id: innerFrame
  name: Inner Frame
  type: { kind: bytes, n: { kind: remaining } }
  next:
    _: ethernet    # always an Ethernet frame; no type discriminator
```

The `next` map is metadata only. Resolution (lookup strategy, multi-file
registry) is the concern of the tool layer, not PSDL.

**Locating the handoff payload.** `next` maps a value to a target name; it does
not by itself identify the wire bytes the codec re-parses (nested deserialize /
raw-packet generation) or the visualizer nests as the linked protocol. That
region is located as follows:

- If `next` is declared on a `bytes` field, that field's bytes **are** the
  payload (as in the VXLAN `innerFrame` example above).
- If `next` is declared on a non-`bytes` discriminator field (e.g. IPv4
  `protocol`, an `int`), the payload is the region beginning at the field
  marked `category: payload-marker` (§5.1); absent any `payload-marker` field,
  it is all bytes remaining in the enclosing scope after the last body field.

**Discriminator expression (GENEVE / conditional linking):**

When the protocol to link to depends on a combination of fields rather than
a single field value, the field carrying `next` may use the `_` catch-all
key with a `when` condition (not yet specified; tool-layer extension). For
current PSDL, the `next` map keys are discrete values of the field on which
`next` is declared. If the target protocol is determined by a different field
(e.g. GENEVE `protocolType` governs the inner frame type but the `next` map
is on the payload bytes field), authors may annotate the payload bytes field
with `next: { _: <default> }` and document the dependency in `doc`; full
conditional linking is a planned extension.

**Cross-layer field access (`enclosingField`):**

An inner PSDL document may reference a named field from the immediately
enclosing protocol layer's parsed state using the `enclosingField`
expression form:

```yaml
{ kind: enclosingField, field: protocolType }
```

`enclosingField` is valid in `constraints` only. It is not valid in body
expressions (forward-reference semantics cannot be guaranteed across layers).
Using `enclosingField` outside a `constraints` expression is a validation
error. The referenced field name must match a field id in the enclosing
layer's PSDL document; if no enclosing layer is present at evaluation time,
the expression yields `0` (same as an absent-field reference). The
enclosing-layer parsed state is a separate env supplied by the codec and is
available during the constraint-evaluate phase (§10.0).

---

## 8. Checksum binding

```yaml
- id: checksum
  name: Header Checksum
  type: { kind: int, bits: 16 }
  category: checksum
  checksumAlgorithm: internet
  checksumCovers: [version, ihl, totalLength, protocol, src, dst]
```

A field carrying `checksumAlgorithm` is computed and filled by the codec on
serialize after the covered fields are encoded (the authored/wire value is
ignored for output), analogous to the `computedFrom` contract for length
fields (§4).

### Algorithms

| Value | Description |
|-------|-------------|
| `internet` | RFC 1071 one's-complement sum (IP, ICMP, IGMP) |
| `crc32` | CRC-32 / ISO 3309 (Ethernet FCS) |
| `crc32c` | CRC-32C / Castagnoli (iSCSI, NVMe) |
| `crc16` | CRC-16 / IBM |
| `adler32` | Adler-32 |

For algorithms not in this list, an arbitrary string may be used. The codec
is responsible for implementing it; PSDL treats it as opaque unless
`checksumParams` is also supplied.

### Algorithm parameters (`checksumParams`)

CRC variants that differ only in polynomial or processing flags can be fully
parameterized without a custom algorithm name:

```yaml
- id: fcs
  name: Frame Check Sequence
  type: { kind: int, bits: 32 }
  category: checksum
  checksumAlgorithm: crc32-custom
  checksumParams:
    polynomial:    0x04C11DB7
    initValue:     0xFFFFFFFF
    finalXOR:      0xFFFFFFFF
    inputReflect:  true
    outputReflect: true
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `polynomial` | integer | Generator polynomial (normal / non-reflected form) |
| `initValue` | integer | Initial register value |
| `finalXOR` | integer | Value XORed with the final CRC |
| `inputReflect` | boolean | Reflect each input byte before processing |
| `outputReflect` | boolean | Reflect the final CRC before XOR |

All `checksumParams` fields are optional. Named algorithms have well-known
implied parameters; `checksumParams` overrides them when present. Tools
SHOULD emit a lint warning when `checksumParams` is used with a well-known
named CRC algorithm (`crc32`, `crc32c`, `crc16`), since the result may not
be the standard algorithm despite bearing its name. Consider using a custom
algorithm name (e.g. `crc32-custom`) to make the deviation explicit.

Using `checksumParams` with a named algorithm that does not use a CRC
parameter model (`internet`, `adler32`) is a validation error. These
algorithms have fixed internal parameters that are structurally incompatible
with the CRC parameter set.

### `checksumCovers` shorthand

`checksumCovers` accepts individual field ids, **ref-container ids**, and
**repeat container ids**. The expansions are:

- A dotted leaf id (e.g. `src.oct0`) — covers that single field.
- A ref-container id (e.g. `src`) — expands to all leaf fields of the
  referenced def in definition order.
- A repeat container's `id` (e.g. `chunks`) — expands to the concatenated
  wire bytes of every iteration in parse order, **including** any `align`
  padding consumed within each iteration. This allows checksums that cover a
  variable number of repeated elements (e.g. SCTP CRC32c over all chunks,
  including inter-chunk padding bytes) to be expressed without enumerating
  each element statically. When a repeat container id appears in
  `checksumCovers`, the expansion includes ALL bytes consumed by each
  iteration regardless of whether individual `align` containers inside the
  iteration have an `id`. The `align` default-exclusion rule (§5) applies
  only to top-level or struct-level checksum fields whose `checksumCovers`
  list does NOT include the enclosing repeat container.

```yaml
checksumCovers: [version, ihl, totalLength, protocol, src, dst]
# 'src' and 'dst' are ref containers → expands to src.oct0…src.oct3, dst.oct0…dst.oct3

checksumCovers: [commonHeader, chunks]
# 'chunks' is a repeat → expands to all byte-ranges of all iterations of that repeat
```

Both dotted forms (`src.oct0`) and container shorthands (`src`, `chunks`) may
be mixed in the same list. Expansion is performed by the codec before checksum
computation.

When a checksum field appears inside a `repeat` element, ids in its
`checksumCovers` resolve within the current iteration's scope (the
repeat-indexed `#N` instance), exactly as `ref` does (§10.4). This makes
per-block interleaved CRCs — e.g. DNP3 data-link frames (IEEE 1815) carrying a
2-byte CRC after each 16-byte block, modelled as a `repeat` of
`{ data, crc }` — expressible: the `crc` field's `checksumCovers` lists its
iteration-local sibling `data`, which resolves to that iteration's `data#N`.

### Pseudo-header (`checksumPseudoHeader`)

TCP and UDP checksums include bytes from the enclosing IP header that are not
part of the TCP/UDP packet definition.

```yaml
- id: checksum
  name: Checksum
  type: { kind: int, bits: 16 }
  category: checksum
  checksumAlgorithm: internet
  checksumPseudoHeader: ipv4
  checksumCovers: [srcPort, dstPort, dataOffset, flags, windowSize,
                   urgentPointer, data]
```

| Value | Pseudo-header contents |
|-------|----------------------|
| `ipv4` | src addr, dst addr, zero, protocol, segment length (RFC 793 §3.1) |
| `ipv6` | src addr, dst addr, upper-layer length, zeros, next header (RFC 2460 §8.1) |

The codec resolves pseudo-header values from the enclosing layer at
serialize/deserialize time.

---

## 9. Constraints

Constraints express equality relationships evaluated independently of body
parsing. They may reference any field regardless of document position.

```yaml
constraints:
  - lhs: { kind: ref, field: totalLength }
    rhs:
      kind: op
      op: "+"
      a: { kind: op, op: "*", a: ihl, b: { kind: lit, value: 4 } }
      b: { kind: ref, field: dataLength }
    doc: totalLength = header + data
```

**Constraint evaluation rules:**

- A constraint is **silently skipped** if any field it references is absent
  (optional not taken, switch arm not selected, ref not expanded).
- A constraint whose `lhs` or `rhs` references a field inside a recursive def
  expansion is **always silently skipped** during evaluation and
  back-propagation (see §6 Recursive defs — Limitations). Tools SHOULD emit
  a lint warning at load time when such a constraint is detected.
- Constraint equality is checked after all present fields have been parsed.
  A mismatch produces a **validation warning** (not a hard error) to allow
  lenient parsing of malformed packets.
- Codec back-propagation: given one side's value, solve for unknown fields on
  the other side. Only **single-unknown linear** expressions can be
  auto-solved; multi-unknown or non-linear constraints are used for validation
  only.
- Back-propagation MUST be **fixpoint-iterated**: the solver re-runs the full
  constraint list until no new fields are resolved in a pass. A single pass
  is insufficient when constraint A resolves field X, enabling constraint B.

---

## 10. Expression evaluation rules

### 10.0 Processing model: `env` and phases

The **env** is the key-value map of resolved field values against which
expressions are evaluated. Keys are field ids (including ref-expanded dotted
ids and repeat-indexed ids); values are integers. Processing proceeds in four
ordered phases:

1. **Seed** — populate the env with `const`/`defaultValue` values (§10.2) and
   any decoder-injected values (e.g. `env[repeat.id]` iteration counts for
   `count: eos` repeats, §10.7, and the **top-level packet bit count** that
   backs `enclosingBits` at the top-level `body`). All seeding happens before
   any parsing or normalization. Note that an `encrypted.plaintext`'s
   `enclosingBits` is **not** seed-injected: it equals the enclosing
   `encrypted` container's `wireBits` expression, which is evaluated when the
   encrypted container is entered during the Parse phase (see §10.1).
2. **Parse** — walk the body in document order, reading wire bytes, evaluating
   body expressions against the current env, and writing each parsed field's
   value into the env as it is read. `peek` (§10.6) reads ahead during this
   phase without consuming.
3. **Normalize** — resolve any positions that depend on counts injected during
   seeding but not produced by parsing (e.g. `eos` repeats default to `0`
   iterations when their `env` key is absent).
4. **Constraint evaluate / back-propagate** — evaluate `constraints` and run
   the fixpoint solver (§9) over the fully-parsed env.

The `eos`/`peek`/`constraint` rules below reference these phases by name.
"Before normalization" means during the seed phase.

The `enclosingField` expression (§4, §7) reads from a **separate
enclosing-layer env** supplied by the codec, not from this document's env. It
is a constraints-only form and is therefore resolved during the
constraint-evaluate phase; it yields `0` when no enclosing layer is present.

### 10.1 Scope (body expressions)

An expression in a body container may reference only fields that appear
**before** the current container in document order (top-to-bottom,
depth-first traversal). This applies to:
`bytes.n`, `repeat.count`, `switch.on`, `optional.when`, `encrypted.wireBits`,
`bounded.bytes`, `virtual.expr`, and `wireSize.target` (in a body expression
the target must precede the `wireSize` expression in document order).

The `peek` expression reads ahead in the stream and is the only expression
that may read data not yet parsed (§4). `enclosingBits` is exempt from the
forward-reference restriction **only at the top-level `body`**, because there
it is a decoder-injected constant available before parsing begins, not a
stream read. Inside an `encrypted.plaintext` struct, `enclosingBits` equals
the result of the enclosing `encrypted` container's `wireBits` expression,
which is evaluated when the encrypted container is entered during parse;
`enclosingBits` there is therefore **subject to the normal forward-reference
rule** — every field referenced by that `wireBits` expression must precede the
`encrypted` container in document order. `constraints` expressions are fully
exempt from this rule.

### 10.2 Default value seeding

Before evaluation begins, values are injected into the env in this precedence
order (highest first):

1. Each field's `const` value, if present. **`const` always wins.**
   If both `const` and `defaultValue` are specified on the same field, the
   `const` value is used and `defaultValue` is ignored for seeding.
2. Each field's `defaultValue`, if present and not already set by `const`.
3. These rules apply recursively inside `defs`, `group`, `optional`, and
   `encrypted` — including fields that may ultimately be
   absent on the wire. For `recursive: true` defs, seeding applies only to
   the fields directly declared in the def body, not to any
   recursively-expanded `ref` instances of the same def. A recursive `ref`
   container within a def is treated as an unresolved boundary for seeding
   purposes, identical to the constraint solver rule in §6.
   When a **body expression** (not a constraint) references a field in a
   recursively-expanded instance, the value is resolved the same way as an
   absent-field reference: the field's seeded value from its def-body
   declaration is used, or `0` if no seed is defined. This matches §10.3
   and is distinct from the constraint solver, which treats such references
   as unresolvable unknowns (§6).

### 10.3 Absent field references

If an expression references a field that is absent (optional not taken,
switch arm not selected, ref not expanded), the env lookup returns the
field's seeded value per §10.2, or `0` if none. This is intentional: it
allows expressions to gracefully handle optional fields without branching.
This rule also applies to fields inside recursively-expanded def instances:
a body expression referencing such a field yields the field's seeded value
from its def-body declaration or `0` (see §10.2 rule 3). Note that constraint
expressions follow a different rule — recursive-boundary fields are treated
as unresolvable unknowns by the constraint solver (§6).

### 10.4 Repeat element scope

Inside a `repeat` element:
- A field may reference earlier fields within the **same iteration** only.
- Fields from previous iterations are not reachable via `ref`.
- The `until` expression is evaluated after each complete iteration and
  may reference any field in the current (just-parsed) iteration.
- For byte-bounded iteration, wrap the repeat in a `bounded` scope with
  `count: eos` (canonical description in §5 Bounded scope).
- The `prevIter` expression (§4) is available in `until` expressions to
  reference a field value from the most recently completed iteration, for
  loop-termination conditions. Cross-iteration invariants (e.g. monotonically
  increasing sequence numbers) are not expressed in PSDL; delegate them to
  §9 constraints or the codec layer (§4 `prevIter` note).

### 10.5 Switch non-selected arms

When a switch arm is not selected:
- Its fields are not parsed and not added to the env.
- References to those fields from later body expressions yield their seeded
  value per §10.2, or `0` (rule §10.3).
- Constraints referencing those fields are silently skipped.

### 10.6 Peek parse position

The `peek` expression reads from the **current parse position** at evaluation
time, defined as follows:

| Context | Current parse position |
|---------|----------------------|
| `switch.on` | First bit of the switch container |
| `optional.when` | First bit of the optional container |
| `repeat.count` (fixed form) | First bit of the first element |
| `repeat.count.until` | First bit **after** the last byte of the just-completed iteration |

In all four contexts the position is the cursor of the **current (innermost)
scope's sub-stream**; `offset` (§4, in bits) advances forward in bits from
there. A `peek` that would read past the innermost scope-providing container's
remaining budget is treated as reading past available data and yields `0`
(§4), even if bytes exist beyond the scope boundary in the underlying buffer.

### 10.7 `eos` repeat iteration count

For `count: eos` repeats, the decoder **MUST** inject the iteration count
into the env during the **seed** phase (§10.0), using the key equal to the
repeat's `id`:

```
env[repeat.id] = <number of complete iterations>
```

If this key is absent (e.g. during static layout preview), the **normalize**
phase defaults to `0` iterations. Tools that stream-decode loop until
end-of-stream is detected and then inject the count.

The decoder/codec **MUST** also populate `env[repeat.id]` for **fixed-count**
repeats (it trivially equals the evaluated `count` expression). This makes a
`ref` to a repeat container's `id` (§4) yield the completed iteration count
uniformly for both `eos` and fixed-count repeats, so a count field can
back-propagate via a constraint `countField == <repeatId>`.

### 10.8 Nested optional evaluation

When an `optional` is nested inside another `optional`:
- The inner `when` is evaluated **only if** the outer optional is present.
- If the outer optional is absent, the inner container is treated as absent
  without evaluating the inner `when`.
- This short-circuit behaviour extends to arbitrary nesting depth.

---

## 11. Error behavior

This section defines the expected behavior for every exceptional condition.
Tools SHOULD follow these classifications; deviation must be documented.

### 11.1 Validation errors (caught at load/parse time)

| Condition | Error |
|-----------|-------|
| Missing required field (`name`, `body`, etc.) | Validation error |
| Field id does not match `[a-zA-Z][a-zA-Z0-9_-]*` | Validation error |
| Field id contains `.` | Validation error |
| `ref` target not found in `defs` or imports | Validation error |
| Circular reference in `defs` through a non-`recursive` path | Validation error |
| `peek` used outside `switch.on` / `optional.when` / `repeat.count` (including `.until`) — e.g. in `bytes.n`, `encrypted.wireBits`, or `constraints` | Validation error |
| `enclosingBits` used outside a scope-providing container that carries an injected bit budget (i.e. outside an `encrypted.plaintext` struct or the top-level `body`) | Validation error |
| `remaining`/`enclosingBits` used inside an `encrypted.plaintext` whose `encrypted` container omits `wireBits` | Validation error |
| `prevIter` used outside `repeat.count.until` | Validation error |
| `enclosingField` used in a body expression (not in `constraints`) | Validation error |
| `switch` case key has invalid format | Validation error |
| `berLength.maxBytes` > 5 | Validation error |
| `remaining` used outside a scope-providing container (a `bounded` scope, `encrypted.plaintext` struct, or the top-level `body`) | Validation error |
| `checksumParams` used with a non-CRC named algorithm (`internet`, `adler32`) | Validation error |
| Field id appears in more than one `rendererHints.sections` entry | Validation error |
| `rendererHints.sections` entry has an empty `fields` list | Validation error |
| `rendererHints.sections.fields` entry does not correspond to any top-level body container or field id | Validation error |
| `align` container `to` value is not a positive power of 2 that is a multiple of 8 | Validation error |
| `lookup` table key is not a non-negative decimal integer | Validation error |
| `lookup` table value is not a non-negative decimal integer | Validation error |
| Two imports share the same `as` prefix | Validation error |
| Import circular chain | Validation error |
| Import `source` cannot be resolved | Validation error |
| `ref` target resolved only through a transitive import (not directly listed in this document's `imports`) | Validation error |
| A `defs` key or imported name re-declares a name already introduced by an `imports` entry | Validation error |
| Import-qualified def name (e.g. `addr.ipv4Addr`) used directly in `checksumCovers` | Validation error |
| `wireSize` in a body expression references a `target` that appears after the `wireSize` expression in document order | Validation error |
| `wireSize` in a body expression targets an enclosing/not-yet-closed (still open on the parse stack) container | Validation error |
| `ref` to a repeat container's `id` in a body expression that precedes that repeat in document order | Validation error |
| `computedFrom` set to any expression other than `wireSize` | Validation error |
| `virtual` field placed inside a `defs` struct body | Validation error |

### 11.2 Runtime errors (during normalization/decode with known values)

| Condition | Error |
|-----------|-------|
| Division or modulo by zero in expression | Runtime error |
| `const` value mismatch | Runtime error |
| `berLength` wire-encoded length > `maxBytes` | Runtime error |
| `varint` field encountered with an encoding string the codec does not implement | Runtime error |
| `remaining` or `enclosingBits` used in a top-level `body` expression when the decoder has not injected the total packet size | Runtime error |
| `align` whose computed padding exceeds the remaining byte budget of the enclosing `bounded` scope | Runtime error |
| `remaining` used to size a `bytes` field while the cursor is mid-byte (not byte-aligned) | Runtime error |

### 11.3 Silent / fallback behavior

| Condition | Behavior |
|-----------|----------|
| Expression references absent field | Yields seeded value (§10.2) or `0` |
| `switch` with no matching case and no `_` | Consume zero bytes (empty struct) |
| `enum` value not in `variants` | Accept as raw integer; no label displayed |
| `varint` overflow | Decoder-defined (truncate or error) |
| Constraint references absent field | Constraint silently skipped |
| Constraint value mismatch | Validation warning (not hard error) |
| `peek` reads past available data | Yields `0` |
| `eos` repeat with no env injection | Zero iterations |
| `lookup` key not found in table | Yields `0` |
| `lookup` key expression truncates to a negative integer | Yields `0` (no key can match; same as key-not-found) |
| Constraint references a field inside a recursive def expansion | Constraint silently skipped at evaluation and back-propagation |

### 11.4 Lint warnings (load-time advisory, not hard errors)

| Condition | Advisory |
|-----------|----------|
| `version` absent from document | Warn that version is undeclared |
| Constraint `lhs` or `rhs` references a field inside a recursive def expansion | Lint warning: constraint will always be silently skipped |
| `checksumParams` used with a well-known named CRC algorithm (`crc32`, `crc32c`, `crc16`) | Advisory: the override changes the effective algorithm; consider using a custom algorithm name instead |

---

## 12. Byte order

`byteOrder` can appear at two levels:
- **Packet level** — default for all multi-byte fields.
- **Field level** — overrides the packet default for `int` and `enum` fields.

### Applicability by type

| Type | Packet-level applies? | Field-level override? |
|------|-----------------------|----------------------|
| `int` | Yes | Yes |
| `enum` | Yes | Yes |
| `bits` (byte-aligned, n a multiple of 8, > 8) | Yes (packet-level only) | No |
| `bits` (any other width, or not byte-aligned) | No (raw MSB-first bit run) | No |
| `bytes` | No (byte-order-agnostic) | No |
| `varint` | No (encoding-defined) | No |
| `berLength` | No (encoding-defined) | No |

The packet-level `byteOrder` applies to a `bits` field **only when it is a
whole number of bytes wide (n a multiple of 8 and greater than 8) and begins
on a byte boundary**. Such a field is read as a multi-byte value subject to byte-order
swapping, exactly like an `int` of the same width, but without a per-field
override. If per-field byte order control is needed for such a field, use
`int` with a mask instead.

Any `bits` field whose width is **not** a multiple of 8, or that begins or
ends mid-byte, is treated as a **raw MSB-first bit run with no byte-order
swap**. Byte-order swapping is defined only over whole bytes, so it cannot
apply to a field that does not occupy whole bytes on a byte boundary (e.g. a
12-bit `bits` field): there is no coherent notion of "which bytes to swap".
Reading such a field proceeds bit-by-bit, most-significant bit first, from the
current cursor position. A preceding sub-byte field that leaves the cursor
mid-byte therefore does not interact with byte-order at all. When an `align`
(§5) follows such a field, the align's round-up applies to this raw bit run:
the cursor is rounded up from its mid-byte position to the next whole byte and
then to the `to` boundary, with no byte-order swap involved.

```yaml
byteOrder: BE
body:
  - id: seq
    name: Sequence Number
    type: { kind: int, bits: 32 }      # inherits BE; per-field override allowed
  - id: leField
    name: LE Field
    type: { kind: int, bits: 16 }
    byteOrder: LE                       # override
  - id: flags
    name: Flags
    type: { kind: bits, n: 16 }        # follows packet-level BE; no per-field override
```

---

## 13. Renderer hints

```yaml
rendererHints:
  rowBits: 32
  sections:
    - id: withdrawn
      label: Withdrawn Routes
      fields: [withdrawnLen, withdrawnRoutes]
    - id: pathAttrs
      label: Path Attributes
      fields: [pathAttrLen, pathAttrs]
    - id: nlri
      label: NLRI
      fields: [nlri]
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `rowBits` | integer | `32` | Bits per row in the wire diagram |
| `sections` | list | `[]` | Visual section labels (display only, no wire semantics) |

`rowBits` at the top level (pre-0.5) is accepted for backward compatibility.

### `sections`

Each section entry declares a labelled visual region:

| Property | Required | Description |
|----------|----------|-------------|
| `id` | yes | Unique identifier for this section |
| `label` | yes | Human-readable section header |
| `fields` | yes | Ordered list of field/group ids belonging to this section |

Sections are display-only; they have no effect on wire layout or expression
scoping. A field not listed in any section is displayed without a section
header.

The following container kinds are valid entries in `sections.fields`:

| Entry kind | Expansion |
|------------|-----------|
| Field `id` | Assigns that single field to the section |
| Group `id` | Assigns the group and all its children to the section |
| Repeat `id` | Assigns the repeat container (all iterations) to the section |
| Switch `id` | Assigns the switch container (all arms) to the section |
| Optional `id` | Assigns the optional container (present or absent) to the section |
| Bounded `id` | Assigns the bounded scope container to the section |
| Encrypted `id` | Assigns the encrypted container to the section |

Any other value (including an id that does not correspond to any body
container or field) is a validation error (see §11.1).

**Section rules:**

- A section `fields` list must not be empty; a section with zero field ids
  is a validation error.
- A field id must not appear in more than one section; a duplicate listing
  across sections is a validation error.
- Section order in `rendererHints.sections` is independent of body field order
  and represents the desired display order only. Renderers SHOULD present
  sections in the order listed and fields within each section in the order
  given in the `fields` list, regardless of their position in `body`.

---

## 14. Codegen hints

Properties used by code generators (Wireshark, scapy, etc.) that carry no
wire semantics.

### `abbrev` — protocol filter name

```yaml
name: tcp
abbrev: tcp   # Wireshark filter: tcp.srcport, tcp.flags, etc.
```

If absent, `abbrev` defaults to `name`. Codegen tools use
`{abbrev}.{field.id}` as the Wireshark filter abbrev for each field. For
synthesized ids, codegen uses the **authored id path joined by `.`** for
ref-expanded fields (`{abbrev}.src.oct0`) and **strips the `#N` repeat-index
suffix** so all iterations of a repeated field share one filter abbrev
(`{abbrev}.options.type`), since `#N` is a runtime instance handle (§6), not
part of the field's protocol name.

### `display` — display hint

```yaml
- id: etherType
  name: EtherType
  type: { kind: int, bits: 16 }
  display: hex   # show as 0x0800, not 2048
```

For numeric fields (`int`, `enum`, `bits`) `display` selects a display base:

| Value | Description |
|-------|-------------|
| `dec` | Decimal (default) |
| `hex` | Hexadecimal |
| `oct` | Octal |
| `bin` | Binary |

For `bytes` fields `display` selects how the payload is rendered, letting
codegen pick a field type (Wireshark `FT_STRING`/`FT_BYTES`/`FT_ETHER`, scapy
`StrField`/`Field`/`MACField`) and visualizers render text or an address
group instead of a hex dump:

| Value | Description |
|-------|-------------|
| `hex` | Raw byte blob, hex dump (default for `bytes`) |
| `ascii` | ASCII text (e.g. HTTP request line, SIP) |
| `utf8` | UTF-8 text |
| `addr` | Structured address (MAC, IPv6, …) |

`display` is **display-only** and carries no wire semantics; for `bytes` it
does not affect parsing or round-tripping.

---

## 15. Version compatibility

The `version` field declares which PSDL specification version this document
targets. The allowed format is the two-part string `"MAJOR.MINOR"` (e.g.
`"0.5"`). The field is optional but strongly recommended.

**Rules:**

- If `version` is absent, tools SHOULD attempt to parse the document and
  SHOULD emit a warning that the version is undeclared.
- If `version` is present and the tool's supported range does not include
  the document version, the tool MUST emit a validation warning.
- A document with a higher `MAJOR` than the tool supports SHOULD be treated
  as a hard error (unknown breaking changes likely).
- A document with the same `MAJOR` but higher `MINOR` SHOULD be parsed
  leniently (ignore unknown top-level properties) and emit a warning.
- Backward compatibility within the same `MAJOR`: a 0.5 tool MUST correctly
  parse any valid 0.4 document. The `rowBits` top-level property is accepted
  for compatibility with pre-0.5 documents.

```yaml
version: "0.5"
```

---

## 16. Design boundary: the forward-only model and end-relative references

PSDL's core parse model is **forward-only, relative, and single-packet**: a
body expression may reference only fields that appear before it in document
order (§10.1), positions are measured relative to the current parse cursor or
an enclosing scope, and a document describes one self-contained packet type.
This is a deliberate constraint — it keeps parsing single-pass and streamable,
enables progressive rendering in the visualizer, and bounds the complexity a
codec generator must implement. Several scattered notes elsewhere in this spec
(§3 DNS name-compression, §3 template-defined layouts, §5 TLS 1.3 inner content
type, §5 RTP/SRTP padding) declare specific patterns out of scope. This section
consolidates the **problem awareness** behind all of them so the boundary is
recorded in one place and can be revisited in a future revision.

### 16.1 The end-relative / backward-reference family

A recognizable family of real protocols places a value at (or near) the **end**
of a region whose purpose is to determine the size or meaning of an **earlier**
field — i.e. parsing an early field correctly requires a value located later in
the stream. PSDL cannot express the data-dependent members of this family,
because doing so would require either reading backward from the end or a
two-pass "scan to end, then rewind" parse.

| Pattern | Example protocols | Expressible today? |
|---------|-------------------|--------------------|
| Fixed-size trailer at a **constant** offset from the end | IPsec ESP `Next Header` + `Pad Length` (last 2 bytes), treated as a blob | ✅ via end-anchored fields (`remaining − <const>`, §5) |
| Trailing octet whose **value sizes an earlier field** | RTP/SRTP padding count (last octet sizes the payload) | ❌ back-off distance is data-dependent |
| **Backward scan** for a delimiter from the end | TLS 1.3 inner content type (last non-zero byte) | ❌ requires reverse scan |
| **Random-access** from an end pointer back into earlier structure | ZIP End-of-Central-Directory → central directory → local headers; DNS name-compression pointers | ❌ requires absolute backward jumps; the whole format is parsed end-first |

The dividing line is precise: **a constant end-offset is expressible** (place
ordinary fields after a `remaining − <const>` data field); **a value-dependent
back-off, a backward scan, or a random-access jump is not.**

### 16.2 The cross-context-state family

A second family requires state established **outside the current packet** (or in
a previously-parsed part of a session) to choose the layout of a later region:

- **MP-BGP / BGP-4 `AS_PATH`** — whether AS numbers are 2 or 4 bytes wide is
  negotiated by the 4-octet-AS capability in an earlier OPEN message
  (RFC 6793), not carried in the UPDATE.
- **IPFIX / NetFlow v9 data records** — field layout comes from a Template
  Record (even when the template rides in the same packet, the data record is
  not self-describing).
- **Delta-coded accumulators** — e.g. a CoAP option's absolute number is the
  running sum of all prior option deltas; there is no fold/accumulator
  primitive (§4 `prevIter` exposes only the most-recent iteration).

These are out of scope for the same root reason: a single PSDL document
describes one self-describing packet type and has no session-state input.

### 16.3 Why these are deferred, not denied

Supporting either family would force a structurally different engine: a
backward/random-access addressing mode (breaking single-pass streaming) or a
session-state input channel (breaking the single-packet model). Both are real,
non-trivial features that several mainstream protocols (RTP, ZIP, MP-BGP,
IPFIX) genuinely need. They are recorded here as **acknowledged limitations**,
not as evidence the protocols are unimportant. A future revision MAY introduce,
in decreasing order of how well it fits the current model:

1. A **bounded backward window** — end-relative addressing limited to a
   fixed-size trailing region (would cover RTP/SRTP padding and ESP
   data/padding separation) without enabling arbitrary random access.
2. A **session-context input** — a declared, codec-supplied state map
   (e.g. negotiated capabilities) referenceable like `enclosingField`
   (would cover MP-BGP ASN width and IPFIX templates).
3. A **fold/accumulator expression** over repeat iterations (would cover
   CoAP absolute option numbers and similar delta-coded lists).

Until then, these patterns are a codec/tool-layer concern: the raw bytes are
always representable (e.g. an RTP payload+padding as one `bytes` blob, an IPFIX
data set as opaque bytes), only their *interpretation* is out of scope.
