# PSDL 0.5 — Packet Schema Definition Language

A YAML-based language for describing the wire format of network protocol packets.
The formal JSON Schema is at `schemas/psdl-0.5.yaml`.

**This document is normative.** `psdl-0.5.ja.md` is a translation provided for
convenience; where the two disagree, this document governs. A change to the
language is made here first, and the translation follows.

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
  - id: totalLength
    name: Total Length
    type: { kind: int, bits: 16 }
    category: length
  - id: dataLength
    name: Data Length
    type: { kind: int, bits: 16 }
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

**Packet set.** A *packet set* (also called a *registry*) is the set of PSDL
documents a tool has activated at one time — e.g. `@packet-schema/presets`, a
user-supplied directory of PSDL files, or a combination. The `name` uniqueness
rule above is scoped to a packet set: two documents in the same active set
MUST NOT share a `name`. `meta.aliases` values carry no uniqueness
requirement, but a tool SHOULD emit a validation warning when two documents in
the same set declare the same alias, or when one document's alias equals
another document's `name` (see §7 for the resolution priority).

### 1.1 Packet metadata (`meta`)

```yaml
meta:
  rfc: 791          # RFC number (integer)
  section: "3.1"    # RFC section (string)
  aliases: [ip, ipv4]       # alternative names for this packet type
  family: ipv4              # optional single grouping key for related documents
  tags: [internet-layer, addressing]   # free-form classification tags
```

All fields are optional. Used by codegen, Chrome extension, and LSP for
disambiguation and cross-reference.

**Classification (`tags`, `family`).** For catalogs/registries that hold many
documents, `meta.tags` (a free-form `string[]`) and `meta.family` (an optional
single grouping key) classify a packet for grouping, search, and layered
listing — e.g. grouping the several BGP message documents under `family: bgp`,
or filtering by a `transport` tag. These are deliberately **open** (like
`aliases`, unlike the closed field-level `category` tokens of §5.1): the
language fixes only the *shape* (`string[]` / `string`) and never the
*vocabulary*. A controlled term list, if a catalog wants one, is governed by the
catalog/tooling layer (lint), not by PSDL — so adding a classification term
never requires a language change.

**Multi-layer RFC provenance.** `meta.rfc` also accepts an object
`{ defined, updates? }` that records the defining RFC and the chain of RFCs that
later updated the field, so an LSP can render "defined by RFC 791, updated by
RFC 2474 §3, RFC 3168 §5". Each `updates` entry is either a bare RFC number or
an object `{ rfc, section? }` naming the section of that updating RFC; the
sibling `meta.section` names the section of the defining RFC. See §5.4 for the
full definition; it is valid at every level that carries `meta`.

### 1.2 Cross-file imports (`imports`)

The `imports` list makes `defs` from other PSDL files available under a
namespace prefix. This is the mechanism for sharing common structs (IPv4
addresses, MAC addresses, TLS extension headers, etc.) across protocol files
without copy-pasting.

```yaml
imports:
  - source: common/addresses.psdl   # a body: [] def-only library (see below)
    as: addr
  - source: "@packet-schema/presets/tls-types"
    as: tls
```

After import, the imported defs are accessible with the prefix:
`ref: addr.ipv4Addr`. Expanded ids follow the same dotting rules:
`addr.ipv4Addr.oct0`.

**Definition-only library documents.** `body` is required, but it may be the
empty array `[]`. A document whose `body` is **exactly** the empty array
(`body.length === 0`) is a *def library*: its role is limited to providing
`defs` to be used as the `source` of another document's `imports`. (A def
library is identified solely by `body: []`; whether its `defs` is empty or
populated does not change this — an empty-`defs`, empty-`body` document is still
a def library, just an unhelpful one.) A library document is not a member of any
packet set for rendering or `next` resolution: tools MUST NOT list a document
whose `body` is the empty array as a registry `next` target, a deep-link
target, or a renderer entry. The `name`-uniqueness rule (§1) still applies to
library documents (so import resolution can diagnose name clashes). A library
document is, like any other document, subject on its own to §6 ref-cycle
validation and §15 version validation. A `body: []` library document MUST still
declare a `name` and a `version` like any other document. To represent a real
protocol that genuinely has zero displayed/`next`-dispatching fields while
keeping registry visibility, place at least one container in `body` (e.g. a
zero-width `virtual`, or an explicit placeholder field) rather than relying on
`body: []`.

**Rules:**

- `source` is a path string interpreted by the tool layer. Two syntactic
  conventions are distinguished for interoperability: a `source` beginning
  with `@` (e.g. `@packet-schema/presets/tls-types`) is a **registry
  reference** whose resolution (package manager, preset bundle, URL scheme)
  is tool-defined; any other `source` (whether or not it begins with `./` or
  `../`) is a **file path** and SHOULD be resolved relative to the directory
  of the importing document. A tool that resolves imports and deviates from
  these conventions MUST document its resolution strategy.
- `as` defines the namespace prefix; must match `[a-zA-Z][a-zA-Z0-9_]*`.
- Two imports must not share the same `as` prefix — validation error.
- Circular imports (A imports B which imports A) are a validation error.
- Imported defs are read-only. Re-declaration is defined precisely as: (i) a
  local `defs` key equal to an import's `as` prefix is a **validation error**
  (a `ref: addr` could otherwise resolve ambiguously between the def and the
  prefix); (ii) two imports sharing one `as` prefix is a validation error (the
  rule above). A local def whose bare name equals a bare def name inside an
  imported file is **legal** — imported defs are only ever accessed through
  their prefix-qualified form, so no collision arises.
- If a `source` cannot be resolved, it is a validation error.
- **Validation layering.** Import-resolution-dependent conditions — an
  unresolvable `source`, a circular import chain, a `ref` target reachable
  only through a transitive import — are detected by **the layer that
  resolves imports** (the tool layer). A core validator that does not resolve
  imports performs only the syntactic and local checks (`source` non-empty,
  `as` format, duplicate `as`, the `defs`-key/`as`-prefix collision above) and
  MUST NOT report resolution-dependent errors it cannot observe. The layer
  that resolves imports MUST re-run §6 ref-cycle detection over the merged def
  set, since a cycle passing through an import boundary is invisible to the
  unresolved-document check.
- **Imported document versions.** The §15 version-compatibility rules apply to
  each document **independently**, including imported ones: a difference
  between the importer's and the imported file's `version` is **not** itself
  an error. An imported document whose version is outside the tool's
  supported range is diagnosed per §15 (warning, or hard error on a higher
  MAJOR); it is *not* reported as "source cannot be resolved".
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
  An import `as` prefix and a local `defs` key therefore share one dotted
  namespace, and declaring both with the same name is a **validation error**:
  `addr.ipv4Addr` would be ambiguous between the imported def and a dotted
  reach into the local def `addr`, and nothing in the grammar separates them.
- **Expanded-id uniqueness.** Within one document, no two declarations may share
  the same **expanded id** while both can be live in the `env` at the same time.
  The *expanded id* of a field/container is the id of the emitted leaf — the
  ref-prefix-joined id (`{ref.id}.{field.id}`, nested as `{a.id}.{b.id}.…`); a
  `group`, `optional`, `bounded`, `encrypted`, or `align` does **not** contribute
  to the prefix, and only `ref` does. The `#N` / `#N_M` repeat-index suffix is a
  runtime instance handle (§6), not part of the expanded id; a `repeat` instead
  opens a distinct id namespace, so its element-field ids never collide with
  non-repeat siblings, and a field repeated across iterations is one declaration
  distinguished at runtime by `#N`. Two declarations that produce the same
  expanded id and can be simultaneously live are a **validation error**.
  **Exception:** two declarations under **different arms of the same `switch`**
  are never live at once, so they MAY reuse an id; a duplicate **inside** one
  arm, or a clash between an arm field and an enclosing-scope field, is **not**
  allowed. A `ref` instantiation id (`{ref.id}`) is itself a key in the parent
  namespace and obeys the same rule. Reusing an authored **bare** id across
  distinct instantiations (the §6 nearest-preceding idiom) is legal as long as
  the resulting expanded ids differ (`first.len` vs `second.len`).
- **Reference existence.** A `ref.field` / `wireSize.target` in a **body** or
  **`constraints`** expression must name an id that is **declared somewhere in
  the document** (a field/container id, a local-ref-expanded dotted id, or a
  repeat id; bare ids resolve after expansion per §6, so a bare id is valid when
  it equals the tail segment of some expanded id). A reference to an id declared
  nowhere is a validation error. A `{id}#N` repeat-indexed form may not appear
  in an expression (the runtime `#N` instance handle is not addressable, §10.4)
  — a validation error. **Scope:** this check covers leaf `ref`/`wireSize` in
  body and `constraints` expressions only. Expressions authored *inside a `def`
  body* (resolved per instantiation), and `prevIter` / `enclosingField`
  references (which name a repeat-iteration slot or an enclosing-layer field, not
  a document id), are out of scope. A dotted target whose head segment is an
  `imports` `as` prefix is **import-qualified**; its resolution is deferred to
  the import-resolving layer (§1.2) and is not checked by the core validator.

---

## 3. Wire types

Every `Field` has a `type` describing how bits on the wire map to a value.

### `int` — fixed-width integer

```yaml
type: { kind: int, bits: 16 }              # unsigned 16-bit
type: { kind: int, bits: 8, signed: true } # signed 8-bit
```

A field with `signed: true` is decoded as a **two's-complement** integer of
the declared bit width (the wire bits are unchanged; only the numeric
interpretation differs). `signed` has no effect on byte order (§12).

An `int` field may carry `subfields` — mask-addressed bit subfields read over
its decoded value (bit 0 = LSB) — to annotate LSB-first / little-endian word bit
packing without misordering bits (§12).

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

**Delimiter-terminated length (`delimiter`).** Besides an expression, `bytes.n` may
take the form `{ delimiter: <byteList> }`. `delimiter` is a non-empty
list of byte integers (each `0`–`255`). The field spans from the current parse
position forward up to **and including** the first complete occurrence of the
delimiter byte sequence; the delimiter is **always consumed** and is part of the
field's wire footprint (and of any `display` rendering — e.g. a CRLF-terminated
HTTP request line displayed as `ascii` includes its trailing `\r\n`). The scan
is forward-only and relative, preserving the §16 parse model. Length is a
decoder-determined value supplied by seed injection (§10.7). This `delimiter`
form (a byte-sequence terminator on a `bytes` field) and the
`repeat.count.until` after-iteration boolean predicate (§5) are unrelated
constructs that share no keyword; the delimiter-not-found and scan-boundedness
rules are given in §10.7 and §11.2.

```yaml
# HTTP/1 request line (CRLF-terminated; CRLF consumed)
- id: requestLine
  name: Request line
  display: ascii
  type: { kind: bytes, n: { delimiter: [13, 10] } }   # CRLF

# NUL-terminated string (SMB1/RTSP)
- id: filename
  name: Filename
  display: ascii
  type: { kind: bytes, n: { delimiter: [0] } }
```

A `bytes` field may carry a `display` hint (§14) to tell display-layer tools
how to render the payload: `ascii`/`utf8` for text (an HTTP request line, SIP,
DNS labels), `addr` for a structured address (MAC, IPv6), or the default `hex`
for an opaque blob. This is **display-only** and carries no wire semantics
(`bytes` round-trips identically regardless).

> **Numeric value reinterpretation (out of scope).** Reinterpreting wire bits
> as IEEE754 floating point, fixed-point (e.g. NTP 16.16/32.32), or BCD/TBCD
> decimal digits is a **codec/tool-layer concern** in 0.5. `int`/`bytes`
> describe wire structure only; `display` (§14) selects a base/rendering and
> never performs value reinterpretation. See §14 for the design note on how a
> future minor may add structured value reinterpretation without overloading
> `display`.

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

Keys are numeric values; values are labels (optionally with doc). A variant is
either a plain string label or an object; the object form carries `label`
(required) and MAY carry `doc`, `level` (absent ≡ `may`, §9.1), and `meta`
(§5.4).

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
| `cbor` | CBOR unsigned integer (major type 0, RFC 8949 §3) |
| `ea-terminated` | Extension-bit: byte LSB=0 means more bytes follow, LSB=1 = last byte (see below) |
| `leb128` | Unsigned LEB128 (WASM, DWARF) |

```yaml
type: { kind: varint, encoding: quic }
type: { kind: varint, encoding: ea-terminated }
type: { kind: varint, encoding: my-custom-scheme }
```

**`ea-terminated`, precisely.** In each byte, bit 0 (the LSB) is the EA /
continuation bit (`0` = more bytes follow, `1` = last byte) and bits 7..1 are
**value bits**. The value is formed by concatenating the 7-bit value groups
**MSB-first**: the first byte on the wire contributes the most-significant
group (the same group order as BER OID subidentifiers, *not* the
little-endian group order of `protobuf`/`leb128`). Formats that interleave
non-value control bits with the address bits — Q.922 Frame Relay address
fields (C/R, FECN, BECN, DE interleaved with the DLCI) and LAPD address
fields (C/R interleaved with SAPI/TEI) — are **not** plain `ea-terminated`
varints and MUST NOT be modelled as one; decompose them with explicit `bits`
fields (and a `switch` on the EA bits if the field is variable-length)
instead.

**`cbor`, precisely.** `cbor` decodes a CBOR unsigned integer per RFC 8949
§3: the initial byte's major type (upper 3 bits) must be `0`, and the
additional-information value (lower 5 bits) selects an immediate value (0–23)
or a 1/2/4/8-byte big-endian argument (24–27). An initial byte whose major
type is not `0`, or whose additional information is 28–31
(reserved/indefinite), is a **runtime error** (§11.2) — the byte count
consumed is indeterminate, the same failure class as an unimplemented
`varint` encoding.

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
switch discriminators, optional conditions, and on both sides of `constraints`
(§9).

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

**Value domain.** Expression values are integers. Implementations MUST evaluate
`+`, `−`, `*`, `/`, `%`, the comparisons, and table lookups exactly for all
operands and results in the closed range `[0, 2^53−1]` (and their negations
arising from `−` or signed references, i.e. down to `−(2^53−1)`). Authors SHOULD
keep every value that participates in an expression within this range; an
expression input — a literal, a referenced field value, a peek result, or an
intermediate result — that a tool can statically prove exceeds it MAY be
reported as a lint advisory (should-level), never a hard error. Bitwise and
shift operators remain 32-bit as defined below. The numeric value a decoder
*stores and displays* for a field (e.g. a 64-bit sequence number, nonce, or
timestamp) is independent of this expression domain and MUST be decoded and
displayed without loss for the field's full declared width up to 64 bits; such
wide values are display values, not expression inputs. Arithmetic `+`, `−`, `*`
whose true result exceeds the guaranteed exact range has decoder-defined
behavior (exact, wrapped, or error), analogous to varint overflow (§11.3);
authors must not rely on a particular overflow mode.

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

The arithmetic and bit-operation semantics are normative:

- `%` is the **truncated remainder** paired with the truncating `/`: the
  result takes the **sign of the dividend** (`-3 % 4 == -3`, not the floored
  or Euclidean `1`). Negative dividends can arise from `-` arithmetic or from
  `signed` field references; authors must not assume a Euclidean modulo.
- `<<` truncates both operands to 32 bits and yields an **unsigned 32-bit**
  result in `0 .. 2^32−1` (`1 << 31 == 2147483648`).
- `>>` is an **arithmetic (sign-propagating) right shift** over the signed
  32-bit interpretation of the left operand.
- `&` `|` `^` truncate both operands to 32 bits and yield a **signed 32-bit**
  result (two's-complement interpretation: `0x80000000 & 0xFFFFFFFF ==
  -2147483648`).

A consequence of the last two rules is that `(1 << 31)` and
`(0x80000000 & 0xFFFFFFFF)` denote the same bit pattern but compare unequal
(`2147483648` vs `-2147483648`). When a high-bit 32-bit value must be
compared, normalise both sides through the same operator family (e.g. mask
both with `&`).

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
- `bits` must be an integer in `1`–`64`. A `bits` value outside `1`–`64` is a
  validation error (§11.1).
- The offset is relative to the **current parse position** at evaluation time.
  The exact definition of "current parse position" for each context is given in
  §10.6.
- If the peeked region extends beyond available data, the result is `0`.
- `peek` is the only expression form that may read data not yet parsed.
- A `peek(b)` with `b` in `54`–`64` feeding `switch.on` / `optional.when` is
  valid wire (the `1`–`64` bound is unchanged), but because its result can
  exceed the guaranteed-exact value domain it MAY draw the should-level
  input-range lint advisory above. That lint is advisory-only.

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
- **"Most recently completed", precisely.** The `until` expression is evaluated
  **after** an iteration is fully parsed. Within that evaluation, an ordinary
  `ref` resolves to the **just-completed** iteration's field value, and
  `prevIter` resolves to the value from the iteration **before** it. So when
  `until` runs after iteration N (N ≥ 1, counting from 0): `ref: tsn` is
  iteration N's `tsn` and `prevIter: tsn` is iteration N−1's `tsn`. `prevIter`
  is the second-most-recent value precisely because the most-recent one is
  already reachable by ordinary `ref`; the pair lets `until` compare the current
  iteration against its predecessor (e.g. `tsn != prevIter(tsn) + 1`).
- On the first iteration (no prior iteration exists), `prevIter.field`
  yields the field's seeded value per §10.2, or `0` if none.
- **Absent in the prior iteration (sticky).** If the referenced field did not
  exist in the immediately preceding iteration (its `switch` arm was not
  selected, or its `optional` was not taken), `prevIter` does **not** reset to
  the seed; it retains the value from the **most recent iteration in which the
  field was present** (sticky). It falls back to the §10.2 seed (or `0`) only
  when the field has not been present in any prior iteration. This matches the
  reference implementation, which overwrites the `prevIter` slot only when the
  prior iteration actually produced the field.
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
- **Sub-byte rounding.** `remaining` is computed from the raw bit gap:

  ```
  remaining = max(0, floor((scope budget in bits - bits consumed in scope) / 8))
  ```

  The subtraction happens in bits and the floor is applied once, at the end.
  Rounding each side separately — `floor(budget/8) - ceil(consumed/8)` — charges
  a partial trailing budget byte *and* a mid-byte cursor, penalising the same
  boundary twice and under-reporting by one whenever a scope's budget is not a
  whole number of bytes (an `encrypted` region with a sub-byte `wireBits`, for
  instance). The two forms agree whenever the budget is byte-aligned, which is
  every case a byte-aligned cursor can observe.

  `remaining` is still only well-defined for sizing a `bytes` field when the
  cursor is byte-aligned; using `remaining` to size data while mid-byte is a
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
| `subfields` | no | Mask-addressed bit subfields over an `int` / byte-aligned `bits` field; display/annotation only (see §12) |

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

These **nine tokens are a closed set**: `category` is constrained to this enum
by the JSON Schema, so any other token is a **validation error** (§11.1). PSDL
0.5 does not provide a token for padding, sequence numbers, or timestamps (use
`reserved` for must-be-zero padding, and leave sequence/timestamp fields
without a `category`); a future MINOR may extend the set. `category` is a
property of `Field`, `group`, and `encrypted` only — an `align` container
**cannot carry a `category`** (its padding bytes are not a semantic field), so
there is no token for alignment padding.

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

#### 5.3 Value dictionaries (`values`)

A field MAY carry a `values` array: an **open** dictionary that annotates
individual discrete values (or inclusive ranges) with meaning, normative
strength, and provenance. It applies to any field whose value space is discrete
— `int`, `bits`, `enum`, `varint`, `berLength`.

`values` is **annotational only**. It does NOT close the value space: a value
absent from the dictionary is still a valid wire value. It carries **no wire
semantics** and has no effect on parsing, layout, or expression scoping. It is
distinct from `next` (§7), which is a dispatch map, and from `enum.variants`
(§3), which supplies display labels and governs raw-integer fallback. A
whole-field `values` dictionary coexists with `subfields` as an independent,
non-exclusive annotation layer; see §12.

Each entry sets exactly one of three matchers:

- `value` — a single value;
- `range` — `[min, max]`, inclusive;
- `pattern` — a **ternary bit-pattern predicate**: a string of `0`, `1`, and
  `x` (don't-care), read like a binary literal (rightmost character = bit 0).
  It matches when every non-`x` bit equals the observed bit. This expresses
  non-contiguous pools a contiguous range cannot, e.g. the DSCP
  experimental/local-use pool whose low two bits are `11` (`pattern: "xxxx11"`,
  equivalently `"11"` — characters beyond the pattern length are don't-care).
  A pattern cannot encode a contradiction, so no extra validation is needed.
  Uppercase `X` is accepted as a synonym for `x` (don't-care); lowercase is the
  canonical spelling. Plain `value` is the fully-specified special case
  (`value: 46` ≡ `pattern: "101110"`); keep `value` for readability. Values MAY
  be negative on `signed` fields.

  **Signed fields and pattern width.** The bit compared at each pattern position
  is a bit of the **decoded numeric value** in **two's-complement** form, not
  the raw field-width wire bits. For a non-negative value the two agree; for a
  **negative** value on a `signed` field the compared bits are the (conceptually
  infinite-width) two's-complement representation, so bit `i` of `-1` is `1` for
  every `i`. Concretely, `pattern` bit `k` (counting from the right, bit 0)
  matches when bit `k` of the decoded value's two's-complement encoding equals
  the non-`x` pattern character; `x` positions are ignored. This is what the
  reference resolver (`matchesPattern`) computes via arbitrary-width arithmetic
  shifts, so patterns wider than 32 bits and negative values are both handled
  without wrap-around. A `pattern` **longer than the field width** is not a
  validation error: positions beyond the field's significant bits simply test
  the sign-extended two's-complement bits of the decoded value (all-zero for an
  unsigned or non-negative field, all-one above the sign bit of a negative
  signed value), so an over-wide pattern is well-defined rather than rejected.

Optional members: `name` (machine symbol), `label` (human label), `doc`,
`level` (§9.1; absent ≡ `may`), and `meta` (`{ rfc?, section? }`, §5.4).

Reverse lookup (value → meaning), used by LSP hover and renderers, resolves in
this order: an exact `value` match always wins; otherwise the first entry (in
array order) whose `range` contains the observed value or whose `pattern`
predicate holds; otherwise none (out-of-list — still valid, just un-annotated).
The reference resolver is `resolveValueEntry`.

Relationship to `enum.variants`: `variants` remains the canonical label table
for `enum` fields and the only structure that affects raw-integer fallback
display (§11.3). `values` is a strictly additive annotation layer usable on
**any** discrete field (including `enum`, where it complements `variants` with
per-value `level`/`meta`). Tools SHOULD prefer `variants` for enum labels and
use `values` for normative/provenance overlays.

```yaml
# IPv4 ToS octet, modern interpretation: DSCP (6 bits) + ECN (2 bits).
- kind: group
  id: tos
  name: Differentiated Services
  meta: { rfc: { defined: 791, updates: [{ rfc: 2474, section: "3" }, { rfc: 3168, section: "5" }] }, section: "1.4" }
  children:
    - id: dscp
      name: DSCP
      type: { kind: int, bits: 6 }
      category: identifier
      # `updates` entries may be bare numbers or { rfc, section? }; the two forms may be mixed.
      meta: { rfc: { defined: 2474, updates: [3260, { rfc: 8622, section: "2" }] }, section: "3" }
      values:
        - { value: 0,  name: CS0, label: "Default / Best Effort", level: should }
        - { value: 46, name: EF,  label: "Expedited Forwarding", doc: "RFC 3246", meta: { rfc: 3246 } }
        - { range: [8, 8], name: CS1, label: "Class Selector 1", meta: { rfc: 2474 } }
        # Non-contiguous pool: any codepoint ending in "11" is experimental/local-use.
        - { pattern: "xxxx11", name: EXP, label: "Experimental / Local Use", level: may, meta: { rfc: 2474, section: "6" } }
    - id: ecn
      name: ECN
      type: { kind: int, bits: 2 }
      category: flags
      meta: { rfc: { defined: 3168 }, section: "5" }
      values:
        - { value: 0, name: Not-ECT, label: "Not ECN-Capable Transport" }
        - { value: 1, name: ECT1,    label: "ECN-Capable Transport (1)" }
        - { value: 2, name: ECT0,    label: "ECN-Capable Transport (0)" }
        - { value: 3, name: CE,      label: "Congestion Experienced", level: must }
```

**Two-stage dictionaries.** A `values` entry annotates a single field's value
space and carries no cross-field condition. When the meaning of one field is
governed by another — ICMP `code` depending on `type`, DNS `rcode` extended by
the OPT pseudo-record, TCP option payloads keyed by `kind` — model it with a
`switch` (§5) on the governing field and attach `values` to the dependent field
**inside each arm**. The selected arm's dependent field then carries exactly the
value dictionary valid for that discriminator, and a tool composes the two-level
meaning (`type` label + arm-local `code` label) from the selected arm. PSDL has
no single-field construct for a condition-dependent value table; the switch-arm
pattern is the canonical form.

**Sharing registry-scale dictionaries.** The canonical way to reuse one large
`values` dictionary (the IANA EtherType registry ~400 entries, DNS RR `TYPE`
~90, etc.) across multiple fields or documents is to wrap the single carrier
field in a one-field `defs` struct and instantiate it with `ref` (locally) or
share it via `imports` (cross-file). Reverse lookup then operates on the
expanded leaf id (e.g. `ethType.value`). A field's declared `values` and `meta`
**MUST be preserved unchanged through `ref` and `imports` expansion**: the
expanded leaf `NormalizedField` carries the same `values`/`meta` as the field
declared in the `def` (see the §5.4 propagation prose and the §6 transparent-
expansion rules). This MUST applies **only to a field's own declared
`values`/`meta`** (the `Field`-level `values` and `Field`-level `meta`); the
`def` (NamedStruct) `meta` itself, and the `meta` of a switch arm / repeat
element / encrypted / bounded / optional region, propagate **only** through the
source AST per §5.4/§6 and do not appear in normalized/layout output (transparent
expansion emits no region field to carry them).

A shared value-dictionary `def` **SHOULD NOT** carry `next`: `next` is
document-local dispatch metadata, and PSDL 0.5 provides no per-instantiation
`next` override. Model document-specific dispatch on a local discriminator
field, not inside a shared `def`. (A per-instantiation `next` override is a
candidate for a future MINOR.)

Enum variants (§3) MAY also carry `level` and `meta`; an absent variant `level`
is `may`, matching value-dictionary entries.

#### 5.4 Multi-layer RFC provenance (`meta.rfc`)

`meta.rfc` accepts either a bare RFC number (the original 0.5 form) **or** an
object `{ defined, updates? }` recording the RFC that originally defined the
field and the ordered chain of RFCs that later updated its layout or semantics.
`defined` is required; `updates` is an ordered (oldest-to-newest) list whose
each entry is either a bare RFC number **or** an object `{ rfc, section? }` where
`rfc` (required) is the updating RFC number and `section` (optional) names the
section of *that* updating RFC. A bare-number `updates` entry carries no section.
A bare number `N` for `meta.rfc` itself is equivalent to `{ defined: N }`. Both
forms are valid at every level that carries `meta` — packet (§1.1), field, group,
optional, struct (both a `defs` struct and the inline structs used as switch
arms, repeat elements, and encrypted plaintext), and bounded/encrypted region.

The sibling `meta.section` names a section of the *defining* RFC — `meta.rfc`'s
`defined` value, or, for the bare-number form `rfc: N`, of RFC `N`. The section
of an *updating* RFC is given by the `section` member of that entry's object
form in `updates`. This is a clarification of the existing single
`meta.section`, not a change to how existing 0.5 documents are read: `meta.section`
has always referred to the field's defining/primary RFC, and the per-update
`section` member is a new, optional refinement.

This lets an LSP render provenance such as "defined by RFC 791, updated by
RFC 2474, RFC 3168" instead of a single number, which is how the one-document,
one-interpretation rule (§16.4) keeps historical reinterpretations as metadata
rather than structural branches. Group-level `meta.rfc` reaches tooling via the
normalized/layout output (`NormalizedField.groupMeta`, `LayoutField.meta`) for
per-group deep-linking. Note: the layout collapses only the **innermost** group;
an outer group that wraps only another group is not surfaced as a `LayoutField`.
On the normalized output, each leaf's `NormalizedField.groupMeta` carries the
meta of the **nearest enclosing group that defines one** — the innermost group's
meta wins, and an outer group's meta is the fallback when the inner groups carry
none — so an LSP that needs nested-group provenance should read the normalized
output. An **encrypted region's** `meta` surfaces on the wire-view blob
`NormalizedField` (alongside the region's `doc`/`category`), and from there on
the `LayoutField`. A **bounded region's** `meta` is documentation-grade
provenance available through the source AST only: `bounded` emits no container
field in the flat normalized model, so its region meta does not appear in the
normalized/layout output (same structural constraint as the nested-group note
above). The same source-AST-only rule applies to the `meta` of an
**optional** region, a **switch arm**, a **repeat element**, and a
**`defs` struct**: these containers are transparent in the flat normalized
model (they emit no container field of their own), so their region meta does
not propagate to the normalized/layout output. Fields inside those regions
remain attributable to their source region through
`NormalizedField.switchCase` / `repeatIndex` / `originalContainerPath`, which
an LSP can use to map an emitted field back to the authored region and its
meta.

> **Note (normative scope of the model names).** `NormalizedField` and
> `LayoutField` name the **reference implementation's output model** (defined in
> `src/types.ts`), not a normative wire structure; they are cited here only to
> describe where each kind of `meta` surfaces. What is normative is the
> **correspondence on the source AST**: every emitted leaf is attributable to
> the authored container that produced it via its **switch-arm key**, its
> **repeat index** (the `#N` / `#N_M` suffix, §6), and its **container path**
> (the ordered list of enclosing container ids from `body` down to the leaf).
> `NormalizedField.switchCase` / `repeatIndex` / `originalContainerPath` are the
> reference implementation's concrete encoding of exactly these three source-AST
> facts. An independent tool MAY use any representation that recovers the same
> three facts; the spec does not mandate these field names or their on-disk
> shape, only that the authored-region attribution be recoverable.

```yaml
meta:
  rfc: { defined: 791, updates: [2474, 3168] }
  section: "1.4"
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
| `meta` | no | RFC annotation `{ rfc?, section? }` for per-region deep-linking (source AST only, §5.4) |

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
`meta { rfc?, section? }` (for per-region RFC deep-linking; like a bounded
region's meta it is available through the source AST only, §5.4).

**`eos` repeat:** End-of-stream detection is decoder-specific. During the
**seed** phase (§10.0), the decoder **MUST** inject the iteration count into
`env[repeat.id]` (under the fully-qualified key of §10.7). If the key is absent,
the normalize phase defaults to `0` iterations.

**`until` repeat — same injection contract.** A `count.until` repeat supplies
its iteration count the **same way** as `count: eos`: the decoder evaluates the
`until` predicate while it streams and injects the resulting completed-iteration
count into `env[repeat.id]` (qualified per §10.7). The model does **not**
re-evaluate `until` during normalize — with no injected count an `until` repeat,
like an `eos` repeat, yields **`0` iterations**. (A tool that tried to
self-evaluate `until` inside normalize would diverge from a streaming decoder,
so the count is always taken from the injected env value.)

**Boundary behaviour.** If a repeat reaches the end of its enclosing
scope-providing container (a `bounded` budget, an `encrypted.plaintext`
`wireBits` budget, or the packet end) **before** an `until` predicate becomes
true, the repeat **terminates at the boundary** — running out of scope is a
normal stop condition, not an error; the unmet `until` simply never fires.
Conversely, if an element parse would **cross** the boundary partway through
(the element is larger than the bytes left in scope), that is the
over-read/under-read case of the enclosing scope (§5 Bounded scope / Encrypted):
an authored `bounded`/`wireBits` budget over-read is a runtime error (§11.2),
and at the packet/injected-data end a truncated element read is the truncated-
capture runtime error (§11.2). This lets a TCP option list (RFC 9293) stop
either on its `EOL`/sentinel `until` or on reaching the end of the options
region, whichever comes first.

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
`meta { rfc?, section? }` (for per-region RFC deep-linking; like a bounded
region's meta it is available through the source AST only, §5.4).

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

- The alignment reference point is the **origin of the byte stream this
  document is parsing** — the first bit of the region handed to this PSDL
  document. `position` below is the parse position measured in bits from that
  origin. Using the document origin — rather than the start of the enclosing
  scope — guarantees that `align` lands on a true wire boundary even when the
  enclosing scope-providing container does not itself begin on a multiple of
  `to` (e.g. a Grouped-AVP `bounded` scope that starts at an arbitrary offset).
  This matches the wire-absolute padding intent of SCTP/Diameter chunk
  alignment (§8).
- **Origin under protocol linking.** When a document is nested via `next` (§7)
  to parse a handoff payload, its origin is the **first bit of the payload
  region passed to it**, not the first bit of the outermost capture buffer.
  Each protocol-linked document parses with its own position counter reset to
  `0` at the start of its region, and `align` boundaries are measured from that
  per-document origin. (The reference implementation normalizes each document
  independently with its position starting at `0`, so an inner protocol's
  `align to: 32` aligns to a 4-byte boundary relative to where that inner
  protocol began, regardless of the byte offset of the payload within the outer
  frame.) For a document parsed at the top level this origin and the absolute
  capture-buffer origin coincide.
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
- **Budget over-/under-consumption.** The scope's `bytes` value is its exact
  byte budget. If the contained containers consume **more** bits than the
  budget (an over-read past the declared boundary), it is a **runtime error**
  (§11.2). If they consume **fewer** bits (an under-read — e.g. a `count: eos`
  repeat that stops short, or trailing bytes no field describes), the cursor is
  **snapped forward to the scope end** so the next sibling container begins
  exactly at the declared boundary; the unconsumed bytes are skipped, not
  re-parsed. This makes the declared `bytes` length authoritative for
  positioning regardless of how much the contents actually read.

### Encrypted

Marks a region as encrypted.

| Property | Required | Description |
|----------|----------|-------------|
| `kind` | yes | `"encrypted"` |
| `id` | yes | Identifier for the encrypted container |
| `plaintext` | yes | Struct describing the decrypted content |
| `wireBits` | no | Expression for the encrypted region size in bits |
| `contextNote` | no | Human-readable note shown in the encrypted-region tooltip |
| `headerProtected` | no | Field ids that are header-protected by the cipher: either inside this plaintext, or a plaintext-external header field declared earlier in the same body (§5; annotation only) |
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

**`headerProtected`.** `headerProtected` lists field ids that are
header-protected by the cipher. Each id MUST resolve either to (a) a field
declared as a **direct field of this encrypted container's plaintext**, or
(b) a field declared in the **same body before this `encrypted` container in
document order** — the plaintext-external header fields a header-protection
scheme reorders or masks (e.g. QUIC's first byte and Packet Number, RFC 9001
§5.4). This is a **presentation-layer annotation only**: it tags the resolved
field in the normalized/layout output (`headerProtected: true`) and never
affects parse position, `wireBits`, scope budgets, or the `env`. The resolution
scope is exactly forward-only same-body: it cannot name a later field or a field
in a different body, and resolution is by the field's **emitted id** (a
top-level/direct header field's emitted id equals its bare id), which both the
validator and the normalizer use as the single resolution set. When a plaintext
field and an earlier same-body field share an id, the **plaintext field wins**
(it is tagged during the plaintext walk; the external pass skips ids that name a
plaintext field). An id that resolves to neither is a validation error (§11.1).
The canonical plaintext-external pattern is QUIC: the long-header `firstByte`
and `packetNumber` are declared as ordinary top-level fields before the
`encrypted` payload container, and `headerProtected: [firstByte, packetNumber]`
tags them.

When `wireBits` is absent, the `encrypted.plaintext` struct has **no defined
byte budget**: `remaining` and `enclosingBits` inside that plaintext have no
defined value and using them is a validation error (§11.1), paralleling the
top-level `body` 'no injected size' rule (§4). Provide `wireBits` whenever the
plaintext contains budget-dependent expressions.

When `wireBits` is present it is the plaintext's exact bit budget, and the
**same over-/under-consumption rule as a `bounded` scope** applies: plaintext
contents that consume **more** bits than `wireBits` are a **runtime error**
(§11.2); contents that consume **fewer** snap the cursor forward to the
`wireBits` boundary so the container after the `encrypted` region begins at the
declared end. (An AEAD tag — e.g. the 16-byte QUIC tag — sits **outside** the
`encrypted.plaintext` budget when `wireBits` measures only the plaintext; size
`wireBits` to the plaintext extent and model any trailing tag as a sibling
`bytes` field after the `encrypted` container.)

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
| `meta` | no | RFC annotation `{ rfc?, section? }` for the def as a whole (source AST only, §5.4) |
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
- After `ref` (and `imports`) expansion, the expanded leaf inherits the source
  field's declared `values`/`meta` unchanged (§5.3/§5.4). The `def`
  (NamedStruct) `meta` itself, and region (switch arm / repeat element /
  encrypted / bounded / optional) `meta`, are source-AST-only and are not
  carried onto the expanded leaf (§5.4).
- In a `repeat` element, the expanded field ids carry both the ref prefix
  and the repeat index: `{ref.id}.{field.id}#N` (e.g. `src.oct0#2`).
- Scope ordering: expanded fields are visible from the position of the `ref`
  container in document order.
- **Unqualified field references inside a def.** An expression authored inside
  a def body (e.g. a `bytes.n` of `{ kind: ref, field: len }` that sizes a value
  by a preceding `len` field in the same def) uses the field's **bare id**.
  After expansion, that bare id resolves to the **nearest preceding field of
  that bare id in document order** — which, inside a single instantiation, is
  the def's own sibling field, so a reusable TLV/length def works per
  instantiation. The resolution is **not** statically scoped to the def: it is
  the same nearest-preceding-bare-id rule used everywhere (§10.1). When two
  instantiations of the same def appear in one body, an expression inside the
  second instantiation resolves a bare id to that instantiation's own field
  (the most recent preceding one), not the first instantiation's. If an
  instantiation must reference a specific other field across instantiations,
  use the fully-qualified `{ref.id}.{field.id}` form; a bare id always binds to
  the nearest preceding occurrence. (The §6 ASN.1 example relies on exactly
  this: `len` inside `asn1Value` sizes the per-instance `value` because `len`
  is the nearest preceding `len` within that instantiation.)
- Constraints are document-level only and cannot be scoped to a single `def`
  instantiation. To express per-instantiation invariants, add them as
  document-level constraints referencing the expanded instantiation ids.

### Recursive defs

When a `def` has `recursive: true`, it may contain `ref` containers pointing
to itself (directly) or to another `recursive: true` def (transitive recursive
link through recursive defs only). The decoder is responsible for enforcing a
reasonable depth limit; the PSDL validator does not impose one.

**Progress and termination.** Every recursive descent **SHOULD consume at least
one bit** of wire on the path to its self-reference (a length, tag, or
discriminator read before the recursive `ref`), so the recursion is bounded by
the finite packet length. PSDL does not statically verify this progress
property — a def that recurses without consuming any bits is structurally valid
but will not terminate on real input, and is an authoring error. Because the
guarantee is dynamic, a static tool (layout/normalize/LSP) that expands a
recursive def for preview **MUST** bound its own expansion: with no
decoder-injected iteration counts the expansion yields **zero** recursive
instances (the `eos`/`until` repeat default of §10.7), so static preview never
descends infinitely. When a decoder reaches its depth limit at decode time, it
**SHOULD** stop descending and treat the over-deep region as opaque `bytes`
(emitting a diagnostic), rather than erroring out the whole parse.

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

**Resolution priority within one packet set.** Within a single packet set (§1),
`name` is unique by rule, but a `meta.aliases` value carries no uniqueness
guarantee. When a `next` value (or a deep-link target) could resolve to more
than one document, the priority is: (1) a document whose **`name`** equals the
value wins over any document for which it is only an **alias**; (2) if it
matches no `name` and is an alias of two or more documents, the resolution is
ambiguous and the tool SHOULD emit a warning and MAY pick deterministically
(e.g. by load order) — PSDL does not mandate which alias-holder wins, only that
a `name` outranks an alias. This is why §1 asks tools to warn when one
document's alias equals another document's `name` (the alias is shadowed) or two
documents share an alias (an ambiguous target): the warning surfaces a
resolution that the `name`-over-alias rule will silently disambiguate or leave
order-dependent.

A document whose `body` is the empty array (`body.length === 0`) is a def
library (§1.2) and MUST NOT be included as a candidate for `next` / alias
resolution. To represent a real protocol with zero fields while keeping
registry visibility, place at least one container in `body` (§1.2).

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
  The payload region **ends** at the end of the enclosing scope (the nearest
  scope-providing container, §4) — i.e. it runs to the scope/packet end, not
  merely to the end of the marker field. A trailer that is part of the current
  protocol (not the handed-off payload) must therefore be modelled as explicit
  end-anchored fields (§5) so it is not swept into the payload region.

**Dispatch semantics of the `next` map.** `next` is metadata only (the
reference validator imposes no checks on it; resolution is the tool layer's
concern), but for interoperable tools its keys follow the **same grammar as
`switch` case keys** (§5): a decimal string is an exact value, `"lo-hi"` an
inclusive range, `"a,b,c"` a value list, and `"_"` the catch-all. Matching uses
the same precedence (exact → list → range → `"_"`). When the discriminator
value matches no key and no `"_"` is present, **no handoff occurs** and the
payload region is left as raw bytes of the current protocol. When a key
resolves to a target `name` the tool cannot find in its active packet set, the
tool SHOULD fall back to rendering the payload as raw bytes and MAY emit a
warning; an unresolved target is **not** a validation error of this document
(the target lives in another document).

**Multiplicity.** PSDL 0.5 does not restrict how many fields carry a `next` map
or how many fields are `category: payload-marker`, and the reference validator
flags neither. When more than one of either exists, the correspondence between a
given `next` map and a payload region is left to the tool layer and is **not
guaranteed deterministic** across tools; authors SHOULD therefore declare at
most one `next` map and at most one `payload-marker` per document so the handoff
is unambiguous. A document needing two genuinely distinct handoff points is
outside the single-payload model this version targets (§16).

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

**Self-coverage (compute the field as zero).** When the checksum field's own id
(or a container that expands to include it) appears in its `checksumCovers`, the
field is fed into the computation **as all-zero bits of its declared width**,
not with its authored/wire value. This is required for algorithms where the
checksum field's contribution does not cancel out: e.g. **SCTP** (RFC 4960 §6.8)
computes CRC32c over the **whole packet with the 4-byte checksum field set to
zero**, so `checksumCovers: [commonHeader, chunks]` (where `commonHeader`
includes the `checksum` field) is computed with those 4 bytes zeroed. For a
one's-complement `internet` sum the zeroing is value-neutral (adding zero leaves
the sum unchanged), which is why IPv4/TCP examples that list the checksum field
work either way; for CRC algorithms excluding the field's bytes entirely would
give a different result, so the zero-substitution rule — not field exclusion —
is the defined behaviour.

**Input stream construction.** The bytes fed to the algorithm are the wire
encoding of the covered elements, concatenated in the **order the ids appear in
`checksumCovers`** (not body/document order), after the container shorthands of
that list are expanded (ref → its leaf fields in def order; repeat → all
iterations in parse order, §"`checksumCovers` shorthand" below) and any
self-covered checksum field is zeroed. A `checksumPseudoHeader` (if present) is
prepended to this stream. Covered fields are concatenated at the **bit level**
in coverage order and the resulting bit string is the algorithm input; when that
bit string is not a whole number of bytes, the codec pads the **final** byte
with zero bits on the least-significant side to a byte boundary before running a
byte-oriented algorithm. Authors SHOULD ensure a checksum covers a
whole-byte-aligned region (the standard case); sub-byte coverage is defined but
unusual.

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
| `polynomial` | integer or 0x hex string | Generator polynomial (normal / non-reflected form) |
| `initValue` | integer or 0x hex string | Initial register value |
| `finalXOR` | integer or 0x hex string | Value XORed with the final CRC |
| `inputReflect` | boolean | Reflect each input byte before processing |
| `outputReflect` | boolean | Reflect the final CRC before XOR |
| `width` | integer (1–64) | CRC width in bits; optional (see **Width** below) |

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

#### Width

The CRC width equals the checksum value field's **declared bit width**
(`int.bits` / `bits.n` / `enum.bits`) — the same "declared width" used by the self-coverage
rule above. The optional `checksumParams.width` (1–64) overrides this for the
rare case where the declared and effective widths differ. A checksum field whose
type has **no single declared bit width** — a `bytes` checksum — **requires** an
explicit `width`: it cannot be derived, so omitting it is a validation error.

#### Integer precision

`polynomial`, `initValue`, and `finalXOR` may each be a bare integer **or** a
`0x`-prefixed hex string matching `^0x[0-9A-Fa-f]+$`. A value at or below
`2^53−1` may be written as a bare integer. A value that needs more than 53 bits
(e.g. the CRC-64/ECMA-182 polynomial `0xAD93D23594C935A9`) **MUST** be written
as a hex string: a bare JSON/YAML integer above `2^53−1` loses precision in an
IEEE-754 double and would corrupt codegen. Tools MUST preserve hex-string params
at full 64-bit precision (BigInt or equivalent). This is a two-layer contract:
the JSON Schema accepts any non-negative integer, but the **validator** rejects a
bare integer above `2^53−1` and directs the author to the hex-string form —
schema acceptance is therefore *not* the same as validity here.

```yaml
- id: crc
  name: CRC-64
  type: { kind: int, bits: 64 }      # width derived from int.bits = 64
  category: checksum
  checksumAlgorithm: crc64-ecma182
  checksumCovers: [data]
  checksumParams:
    polynomial: "0xAD93D23594C935A9"  # > 2^53−1 → hex string (bit-exact)
    initValue:  "0xFFFFFFFFFFFFFFFF"
    finalXOR:   "0xFFFFFFFFFFFFFFFF"
    inputReflect:  true
    outputReflect: true
```

A `checksumParams` block with no `checksumAlgorithm` is still subject to the
width rule above (a `bytes`-typed checksum field with params but no `width` is a
validation error); the non-CRC-algorithm exclusion only fires when a
`checksumAlgorithm` naming `internet`/`adler32` is present.

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

A constraint is exactly an **`lhs == rhs` equality**; PSDL 0.5 has no
inequality constraint form. RFC "MUST" rules phrased as inequalities (`ihl >=
5`, `ttl > 0`, `totalLength <= 65535`) **cannot** be authored as
`constraints` — this is a recorded limitation of the current version, not an
oversight to be worked around with a new key. (A comparison **operator**
(`>=`, `<`, …) may still appear *inside* an `lhs`/`rhs` expression, where it
yields `0`/`1`, e.g. `lhs: (ihl >= 5)`, `rhs: 1`; but that is an equality whose
sides happen to contain a comparison, evaluated only for the validation
diagnostic — the single-unknown linear solver (§9.1) does not invert a
comparison, so such a constraint never back-propagates a value. A range-check
RFC rule is otherwise left to the codec/lint layer.)

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
  The severity of a mismatch is governed by the constraint's `level` (§9.1): a
  **`must`** (or level-less) mismatch is a **hard conflict** (the solver surfaces
  it as `conflict` and `validateConstraints` reports it as a `must`-level
  diagnostic), while a **`should`**/**`may`** mismatch is a non-fatal advisory
  (warning / informational) that never blocks parsing. Wire parsing itself is
  still lenient — a constraint mismatch never changes a wire-parsed field value
  and never aborts the Parse phase; the "hard conflict" is a back-propagation /
  validation result, reported after parsing, not a parse-time abort. (Earlier
  drafts described every mismatch as a plain "validation warning"; the
  authoritative rule is the level-governed behaviour of §9.1.)
- Codec back-propagation: given one side's value, solve for unknown fields on
  the other side. Only **single-unknown linear** expressions can be
  auto-solved; multi-unknown or non-linear constraints are used for validation
  only.
- Back-propagation MUST be **fixpoint-iterated**: the solver re-runs the full
  constraint list until no new fields are resolved in a pass. A single pass
  is insufficient when constraint A resolves field X, enabling constraint B.

### 9.1 Normative levels and the solver

A constraint MAY carry `level: must | should | may`. **Absent ≡ `must`**,
preserving legacy 0.5 behaviour.

Only `must` constraints (including level-less ones) participate in
back-propagation: the fixpoint solver (`propagateFixpoint`, §9) may use them to
resolve unknown field values. `should` and `may` constraints are
**diagnostic-only**: they are never used to derive a field value, and a
mismatch is reported as a lint/validation advisory whose severity follows the
level (`should` → warning, `may` → informational). This guarantees that
relaxing a constraint to `should`/`may` can never change any wire-parsed field
value; it can additionally drop solver-derived values and the hard-failure
detection that the `must` constraint was providing, in exchange for a
level-tagged diagnostic. The rule is enforced structurally in the solver:
`should`/`may` are skipped in `propagate` (back-propagation) and evaluated for
diagnostics only, in `validateConstraints`. Every failing constraint — `must`
included — is reported as an indexed diagnostic, so tooling can map each
violation back to its source constraint; the hard `conflict` is derived from
the first failing `must` in declaration order. A solver conflict
(`propagate`/`propagateFixpoint`) likewise SHOULD identify the conflicting
constraint by index and MAY expose the partially-propagated environment at the
moment of conflict, so tooling can reproduce the conflict (e.g. by re-running
`validateConstraints` over that environment) and attach it to a source range.

The same `must`/`should`/`may` vocabulary applies to value-dictionary entries
(§5.3) and enum variants (§3), where it expresses the normative strength of a
particular value rather than a relationship; value-entry `level` defaults to
`may` and never feeds the solver.

A value-entry `level` is a **presentational annotation about how the RFC treats
that observed value** — the strength with which the standard requires this
value's interpretation or its implementation support — **not** an operational
predicate the tooling acts on. It produces **no diagnostic**: a tool does not
warn, error, or back-propagate from it. Its only use is **rendering emphasis**
(e.g. an LSP hover or a packet view styling a `must` codepoint more prominently
than a `may` one). It deliberately does not distinguish "must send this value",
"must apply this interpretation on receipt", and "must implement support for
this codepoint"; PSDL records only the single normative-strength tag and leaves
that finer reading to documentation, because acting on it would require
send/receive/role context a single packet schema does not carry. This keeps the
value-entry `level` side-effect-free in the reference implementation, matching
the solver-exclusion above.

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

Beyond document order, every body/`constraints` `ref`/`wireSize` target must
also **exist** somewhere in the document (§2): a target naming nothing declared
is a validation error, and a `#N` repeat-indexed form may not appear in an
expression. The forward-order rule additionally rejects a field that refers to
**itself** (a self-size `ref`, or an `optional.when` referencing its own
container) because the target does not yet precede the expression. This does
**not** reject the canonical "present-bitmap extension chain" idiom (Radiotap
RFC, the IEEE 802.11 radiotap `it_present` words): there each `optional.when`
references the **previous, already-closed** present word (`present0`,
`present1`, …), not its own container, so every reference resolves to a
preceding declaration.

Within a `repeat.count` or `repeat.count.until` expression, an ordinary `ref`
to a field of the **same repeat's element** is **exempt** from the
forward-reference rule: such a `ref` resolves to that field's value in the
**just-completed iteration** (§10.7), so it is a backward reference into the
iteration that has already been parsed, not a forward reference. The repeat
container's **own** `id` (a self-size ref to the repeat) and any **non-element
sibling** declared later in document order remain **subject** to the
forward-reference rule — the exemption covers only fields of that repeat's
element. (Concretely, the §5 sentinel example whose `count.until` compares an
element field `labelLen` against `0`, and the `tsn != prevIter(tsn) + 1` idiom
of §4, both rely on this exemption.) Such a `ref` MUST use the element field's
**bare** id (`tsn`), the nearest-preceding form used everywhere in §10.1 — the
repeat-prefixed dotted form (`items.tsn`) is not the supported idiom here.

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

**Seed-phase timing, reconciled.** An `eos` (or `until`) iteration count is by
nature only known *after* the stream is consumed, which appears to contradict
the §10.0 rule that "all seeding happens before any parsing." The reconciliation
is that the count is a **decoder-supplied input to the model's seed phase**, not
a value the model computes during its own parse: a streaming decoder runs its
own read loop to end-of-stream first, *then* presents the resulting count to
PSDL's four-phase model as a seed input (exactly as it presents the top-level
packet bit count). From the model's point of view the value is already known at
seed time; from the decoder's point of view it was discovered by an earlier,
decoder-internal pass. Static tools that have no decoder pass simply omit the
key and get the `0`-iteration default. This is the same injection contract as
`enclosingBits` at the top-level body.

**Per-instance keys for nested / ref-expanded repeats.** A bare `repeat.id` is
insufficient when a repeat is reached more than once — nested inside an outer
repeat, or expanded from a `ref` instantiated multiple times — because each
runtime instance has a **different** iteration count. The key is therefore the
repeat's **fully-qualified id**: the ref-prefix path plus the repeat id plus the
repeat-index suffix, `{prefix}.{id}#N`, with multi-level nesting joining the
indices with `_` (`#0_1` = outer iteration 0, inner iteration 1), matching the
expanded-id scheme of §6. The decoder injects the count under this qualified key
for each instance; a lookup falls back to the bare `repeat.id` only when no
qualified entry exists (the single-instance case). The same qualified key backs
a `ref` to the repeat id (§4) so it resolves to the count of the instance in
scope, not a leaked sibling count.

The decoder/codec **MUST** also populate this key for **fixed-count**
repeats (it trivially equals the evaluated `count` expression). This makes a
`ref` to a repeat container's `id` (§4) yield the completed iteration count
uniformly for both `eos` and fixed-count repeats, so a count field can
back-propagate via a constraint `countField == <repeatId>`.

**Delimiter-terminated `bytes` length (`delimiter`).** A delimiter-terminated
`bytes` field (§3) follows the same injection contract: the decoder scans
forward to the delimiter, then injects the resulting byte length (delimiter
included) into the env during the seed phase under a **dedicated, namespaced
key** keyed by the field's fully-qualified id — distinct from `env[id]` (the
field's value slot) and from every other injection key, so the two never
collide. With no injection (static layout preview) the field's length is
**unknown** and the normalize phase lays it out as `0` bytes; a static
LSP/renderer should present it as a delimiter-terminated variable field of
indeterminate length rather than claim a concrete size.

The forward delimiter scan **MUST** be bounded by the nearest enclosing
scope-providing container with a defined budget: when the field is inside a
`bounded` scope or an `encrypted.plaintext`, a delimiter not found within that
scope's remaining budget — equivalently, an injected delimiter length that
pushes the cursor past the scope's `bytes`/`wireBits` budget — is a
truncated-capture runtime error (§11.2), the same over-consume rule §5 already
mandates for those scopes. For a top-level delimiter-terminated field with no
such enclosing budgeted scope, a decoder that reaches the injected end of
available data without finding the delimiter SHOULD likewise treat the field as
a truncated capture (§11.2). The `delimiter` byte-sequence terminator is
unrelated to the `repeat.count.until` after-iteration predicate (§5); the two
share no keyword.

**Decoder-injected field widths.** Three wire types have no static width and
take the same injection contract as the iteration count above: the decoder
supplies the width during the seed phase, keyed by the field's
**fully-qualified id** (the ref-prefix path plus the field id plus any
repeat-index suffix — §6), never the bare id.

| Type | Env key | Injected value |
|---|---|---|
| `varint` | `__varintBits__{qualified-id}` | the encoded value's wire width, in **bits** |
| `berLength` | `__berLen__{qualified-id}` | the length octets' wire width, in **bits** |
| `bytes` with a delimiter-terminated `n` | `__bytesDelimLen__{qualified-id}` | the payload length, in **bytes** |

The value slot and the width slot are distinct: `env[fieldId]` holds a decoded
*value*, and these keys hold a *width*. A `varint` therefore occupies two
independent entries.

When the key is absent — static preview with no decoder pass — the normalize
phase falls back to a fixed width:

| Type | Static default | Rationale |
|---|---|---|
| `varint` | `0` bits | No minimum is meaningful without the value; the field contributes nothing to a static layout. |
| `berLength` | `8` bits | The BER short form is a single octet, so one byte is both the minimum and the overwhelmingly common case; rendering it is more useful than rendering nothing. |
| `bytes` (delimited) | `0` bytes | The length is unknown until the delimiter is found. |

The asymmetry between `varint` and `berLength` is deliberate and is stated here
so that a reader does not have to infer it from an implementation. Renderers
**MUST NOT** treat a defaulted width as a decoded one.

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

**No machine-readable error codes (this version).** PSDL 0.5 does not assign a
stable machine-readable code to each condition; a condition is identified by its
**section number plus the table row text** in §11.1–§11.4. Consumers that need a
diagnostic identifier (an LSP `Diagnostic.code`, per-rule suppression, i18n, or a
"deviation must be documented" conformance statement) MUST map these rows to
their own code namespace; a normative code scheme is a candidate for a future
revision, not part of 0.5.

### 11.1 Validation errors (caught at load/parse time)

| Condition | Error |
|-----------|-------|
| Missing required field (`name`, `body`, etc.) | Validation error |
| Field id does not match `[a-zA-Z][a-zA-Z0-9_-]*` | Validation error |
| Field id contains `.` | Validation error |
| Two declarations produce the same **expanded id** and can be live in the `env` at the same time (i.e. not in different arms of one `switch`) (§2) | Validation error |
| A body or `constraints` expression `ref` / `wireSize` target is not declared anywhere in the document (§2) | Validation error |
| A body or `constraints` expression `ref.field` contains `#` (a repeat-indexed instance is not referenceable, §10.4) | Validation error |
| `ref` target not found in `defs` or imports | Validation error |
| Circular reference in `defs` through a non-`recursive` path | Validation error |
| `peek` used outside `switch.on` / `optional.when` / `repeat.count` (including `.until`) — e.g. in `bytes.n`, `encrypted.wireBits`, or `constraints` | Validation error |
| `peek` `bits` is not an integer in the range `1`–`64` | Validation error |
| `enclosingBits` used outside a scope-providing container that carries an injected bit budget (i.e. outside an `encrypted.plaintext` struct or the top-level `body`) | Validation error |
| `remaining`/`enclosingBits` used inside an `encrypted.plaintext` whose `encrypted` container omits `wireBits` | Validation error |
| `prevIter` used outside `repeat.count.until` | Validation error |
| `enclosingField` used in a body expression (not in `constraints`) | Validation error |
| `switch` case key has invalid format | Validation error |
| `berLength.maxBytes` > 5 | Validation error |
| `bytes.n` `delimiter` is an empty array (§3) | Validation error |
| `bytes.n` `delimiter` has an element outside `0`–`255` (§3) | Validation error |
| `remaining` used outside a scope-providing container (a `bounded` scope, `encrypted.plaintext` struct, or the top-level `body`) | Validation error |
| `checksumParams` used with a non-CRC named algorithm (`internet`, `adler32`) | Validation error |
| A `headerProtected` id resolves to neither a plaintext field of its `encrypted` container nor a field declared earlier in the same body (§5) | Validation error |
| `checksumParams` `polynomial`/`initValue`/`finalXOR` is a bare integer above `2^53−1` (write it as a `^0x[0-9A-Fa-f]+$` hex string) (§8) | Validation error |
| `checksumParams` `polynomial`/`initValue`/`finalXOR` hex string does not match `^0x[0-9A-Fa-f]+$` (§8) | Validation error |
| `checksumParams` on a field whose type has no single declared bit width (e.g. `bytes`) without an explicit `width` (§8) | Validation error |
| `subfields` on a field that is not an `int` or a byte-aligned `bits` field (§12) | Validation error |
| A `subfields` `mask` does not fit within the field's declared bit width (`mask ≥ 2^bits`) (§12) | Validation error |
| A `subfields` `mask` is neither a non-negative integer nor a `^0x[0-9A-Fa-f]+$` hex string (§12) | Validation error |
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
| A body expression `ref` target appears after the `ref` expression in document order, or refers to its own container (a self-size `ref`, e.g. a field whose `bytes.n` references its own id) (§10.1). **Exempt:** a `repeat.count`/`repeat.count.until` `ref` to a field of the same repeat's element, which resolves to the just-completed iteration (§10.7). | Validation error |
| `computedFrom` set to any expression other than `wireSize` | Validation error |
| `virtual` field placed inside a `defs` struct body | Validation error |
| A `values` entry sets none, or more than one, of `value` / `range` / `pattern` (§5.3) | Validation error |
| A `values` entry `pattern` is empty or contains a character other than `0`, `1`, `x`/`X` (§5.3) | Validation error |
| A `values` entry `range` is not a two-integer `[min, max]` with `min ≤ max` (§5.3) | Validation error |
| A `values` entry `name`/`label`/`doc`, an enum variant object `label`/`doc`, or a constraint `doc` is not a string | Validation error |
| A `values` entry, enum variant object, constraint, or `meta` object carries an unknown key | Validation error |
| A `level` (on a constraint, `values` entry, or enum variant) is not `must`, `should`, or `may` (§9.1) | Validation error |
| `meta.rfc` is neither an integer nor `{ defined, updates? }` where each `updates` entry is an integer or `{ rfc, section? }` (§5.4) | Validation error |
| `category` is a token outside the closed nine-token set (§5.1) | Validation error |

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
| A `bounded` scope's contents consume more bits than its `bytes` budget (over-read past the declared boundary, §5) | Runtime error |
| An `encrypted.plaintext`'s contents consume more bits than the `wireBits` budget (over-read past the declared boundary, §5) | Runtime error |
| A fixed-width field, `bytes.n` (including its delimiter-terminated `delimiter` form, whose delimiter is not found before the injected end of available data, §10.7), or `align` read runs past the decoder-injected end of available data (truncated capture, §5/§10.0/§10.7) | Runtime error |

### 11.3 Silent / fallback behavior

| Condition | Behavior |
|-----------|----------|
| Expression references absent field | Yields seeded value (§10.2) or `0` |
| `switch` with no matching case and no `_` | Consume zero bytes (empty struct) |
| `enum` value not in `variants` | Accept as raw integer; no label displayed |
| `varint` overflow | Decoder-defined (truncate or error) |
| Constraint references absent field | Constraint silently skipped |
| Constraint value mismatch (`should`/`may` level) | Validation advisory (warning / informational); parsing continues |
| Constraint value mismatch (`must` / level-less) | Hard conflict reported after parsing (§9.1); parsing itself is not aborted |
| `peek` reads past available data | Yields `0` |
| `eos` repeat with no env injection | Zero iterations |
| `lookup` key not found in table | Yields `0` |
| `lookup` key expression truncates to a negative integer | Yields `0` (no key can match; same as key-not-found) |
| Constraint references a field inside a recursive def expansion | Constraint silently skipped at evaluation and back-propagation |
| `bytes.n` expression evaluates to a negative byte count | Clamped to `0` (the field occupies zero bytes) |
| `bounded`/`encrypted.plaintext` contents under-read the budget (consume fewer bits than declared) | Cursor snapped forward to the scope/`wireBits` end; unconsumed bytes skipped (§5) |
| `count: eos` repeat where the scope budget is exhausted, or the remaining budget is non-zero but smaller than the next element's minimum size | Repeat terminates (no further iteration is started) |

### 11.4 Lint warnings (load-time advisory, not hard errors)

| Condition | Advisory |
|-----------|----------|
| `version` absent from document | Warn that version is undeclared |
| Constraint `lhs` or `rhs` references a field inside a recursive def expansion | Lint warning: constraint will always be silently skipped |
| `checksumParams` used with a well-known named CRC algorithm (`crc32`, `crc32c`, `crc16`) | Advisory: the override changes the effective algorithm; consider using a custom algorithm name instead |
| Two `subfields` masks overlap, or a subfield `mask` is `0` (§12) | Advisory: subfield masks should be non-overlapping and non-zero |
| A multi-subfield bit run sits under `byteOrder: LE`; consider expressing it with `int` + `subfields` (masks over the decoded value) rather than a sequential MSB-first bits-group (§12) | Advisory: a sequential bits-group mis-packs LSB-first LE words |

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

### LSB-first / little-endian word subfields (`subfields`)

A naive `bits` decomposition cannot express **LSB-first** bit packing inside a
little-endian word: the byte-order swap reorders bytes, so a sequential
MSB-first bits-group lands on the wrong bits (802.15.4 / 802.11 Frame Control,
CAN-Intel signals). The canonical form is an `int` (or a **byte-aligned** `bits`)
field carrying a `subfields` array whose **masks are read over the decoded
value**, with **bit 0 = the least-significant bit** — identical to
`ValueEntry.pattern`'s bit-0=LSB convention (§5.3). Each subfield's decoded value
is `(fieldValue & mask) >> lowestSetBit(mask)`. Because the convention is defined
over the **byte-order-resolved decoded value**, it is byte-order-independent and
works identically for LE and BE words — which is exactly why it succeeds where
the MSB-first bits-group fails.

`subfields` is permitted only on an `int` field or a **byte-aligned** `bits`
field (`n` a multiple of 8); on any other type it is a validation error. Each
`mask` must be a non-negative integer (or a `^0x[0-9A-Fa-f]+$` hex string for
masks wider than 53 bits, decoded at full 64-bit precision per the §8 precedent)
and must fit within the parent's declared bit width (`mask < 2^bits`, else a
validation error). Overlapping or zero masks are a §11.4 **lint** warning, not an
error (real Frame Control fields are non-overlapping, but tools should not
hard-fail). Subfields are **display/annotation only**: they consume no wire bits,
add no parse semantics, do not appear in `env`, and do not affect
`checksumCovers`, expressions, or scoping. Their `values`/`meta`/`level`/
`category` ride through to the normalized output (`NormalizedField.subfields`)
for LSP hover and codegen. They are exposed via `NormalizedField.subfields`
**only**; because exact wire-render placement is not guaranteed in 0.5 (above),
mask-addressed subfields are intentionally **absent from `ResolvedLayout`** — a
renderer that needs subfield value-decode reads them from the normalized output,
not from layout cells.

A field **MAY** carry both a whole-field `values` dictionary (§5.3) and
`subfields`; the two are independent, non-exclusive annotation layers and are
**not** a conflict. A whole-field `values` entry is a reverse-lookup over the
field's entire decoded value; each subfield's `values` annotates only that
subfield's masked sub-value `(fieldValue & mask) >> lowestSetBit(mask)`. A tool
**MAY** surface both (the whole-value meaning and the per-subfield meanings) —
neither overrides the other, and neither carries wire semantics (§16.4).

```yaml
# IEEE 802.15.4 Frame Control, a little-endian 16-bit word (RFC-free; IEEE std).
byteOrder: LE
body:
  - id: fcf
    name: Frame Control
    type: { kind: int, bits: 16 }
    display: hex
    subfields:
      - { id: frameType,    name: Frame Type,         mask: 0x0007, category: type,
          values: [ { value: 1, label: Data }, { value: 2, label: Ack } ] }
      - { id: secEnabled,   name: Security Enabled,    mask: 0x0008, category: flags }
      - { id: framePending, name: Frame Pending,       mask: 0x0010, category: flags }
      - { id: ackReq,       name: Ack Request,         mask: 0x0020, category: flags }
      - { id: panIdComp,    name: PAN ID Compression,  mask: 0x0040, category: flags }
      - { id: reserved,     name: Reserved,            mask: 0x0380, category: reserved }
      - { id: destAddrMode, name: Dest Addr Mode,      mask: 0x0C00, category: type }
      - { id: frameVersion, name: Frame Version,       mask: 0x3000, category: identifier }
      - { id: srcAddrMode,  name: Src Addr Mode,       mask: 0xC000, category: type }
```

> **Render position (this version).** `subfields` carry **value-decode**
> semantics (the decoded sub-value, its `values` dictionary, and its `category`)
> for LSP hover and codegen. The mapping from a subfield's value bit range to a
> concrete **wire render position** — which for a little-endian word is
> generally **non-contiguous** after the byte swap — is **not guaranteed by
> 0.5**: a renderer MAY derive sub-cell positions from the masks, but exact
> sub-cell placement (and the non-contiguous LE case in particular) is a
> candidate for a follow-up revision. This keeps 0.5's one-document,
> one-interpretation guarantee (§16.4) intact for the value-decode layer while
> deferring the render-geometry layer.

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

**Status: metadata only.** Like the `next` map of §7, `sections` is metadata
that the reference validator imposes no checks on; consuming it — and deciding
what to do with a malformed entry — is the tool layer's concern. The shape above
is normative so that tools agree on how to read a well-formed document, but a
document is not invalid for getting it wrong.

For interoperable tools the intended reading is:

- A section `fields` list is expected to be non-empty; a section with zero
  field ids labels nothing.
- A field id is expected to appear in at most one section. A renderer that
  encounters a duplicate SHOULD use the first listing and ignore the rest.
- An entry that names no body container or field has nothing to assign and
  SHOULD be ignored.
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

> **Design note (value reinterpretation).** A future minor (0.6) that adds
> float/fixed/BCD value decoding SHOULD NOT overload the `display` string enum.
> It SHOULD add a separate optional structured property whose shape can be
> validated against the field's declared bit width, e.g.
> `valueType: { kind: float }` or
> `valueType: { kind: fixed, intBits: 16, fracBits: 16, signed?: true }`,
> keeping `display` a pure base/format hint. Consuming such decoded values from
> normalized output additionally requires propagating `display`/`valueType`
> onto `NormalizedField` at that time.

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

### 16.2 The cross-context-state / accumulated-state family

A second family needs **runtime-accumulated state that PSDL's static,
forward-only, single-pass model does not thread through** — to choose the layout
of a later region or to reconstruct a value. The state may live **outside the
current packet** (session/connection context) **or** be **accumulated within the
packet** as parsing proceeds; the common obstruction is that no PSDL primitive
carries a running, parse-time-built table or counter from an earlier region into
a later one. To classify a new pattern, ask: *does correctly interpreting a
later region require a value or table that is built up while parsing rather than
read from a single discriminator field?* If yes, it is in this family and out of
scope. The members span both the cross-packet and intra-packet ends of that
criterion:

- **MP-BGP / BGP-4 `AS_PATH`** (cross-packet) — whether AS numbers are 2 or 4
  bytes wide is negotiated by the 4-octet-AS capability in an earlier OPEN
  message (RFC 6793), not carried in the UPDATE.
- **IPFIX / NetFlow v9 data records** (same-packet or cross-packet) — field
  layout comes from a Template Record; even when the template rides in the same
  packet, turning the parsed template entries into the *structure* of the data
  record requires runtime-built layout state the model cannot materialize (§3
  template-defined record layouts).
- **HTTP/2 HPACK dynamic table** (intra-block **and** connection state) — a
  header field can be a back-reference into a dynamic table that earlier entries
  in the *same* header block (and earlier blocks on the connection) appended to;
  decoding a later index requires the running table built while parsing the
  preceding entries. This is the most prominent member and is **explicitly out
  of scope** — both its intra-block accumulation and its connection-lifetime
  persistence put it squarely in this family.
- **Delta-coded accumulators** (intra-packet) — e.g. a CoAP option's absolute
  number is the running sum of all prior option deltas; there is no
  fold/accumulator primitive (§4 `prevIter` exposes only the most-recent
  iteration). Note the wire *structure* of each CoAP option is still
  self-describing (§3 CoAP switch idiom); only the reconstructed absolute number
  needs the accumulator, so this is a value-reconstruction member of the family,
  not a structural-parse one.

These are out of scope for the same root reason: a single PSDL document
describes one self-describing packet type, parsed in one forward pass, with no
session-state input and no parse-time accumulator that survives across regions.
(The earlier wording "state established outside the current packet" named only
the cross-packet end of this family; the criterion above is the intended one and
covers the intra-packet accumulator members — CoAP deltas, HPACK intra-block
indices — equally.)

**Multi-field protocol dispatch.** A related current-version limitation: `next`
(§7) dispatches on the **discrete values of a single field**. A protocol whose
upper layer is chosen from a *combination* of fields — the canonical case being
TCP→HTTP, where the application protocol is keyed on `srcPort` **OR** `dstPort`
(either side may be the well-known port) — cannot be expressed, because `next`
has no multi-field or OR-of-fields key form. The planned `when`-conditional
linking sketch (§7, for GENEVE) is also single-condition and does not cover a
two-field OR. This is recorded as a **constraint of the current version**, not a
new construct to be added here; until a conditional-linking extension lands,
such a handoff is annotated with `next: { _: <default> }` plus a `doc` note (§7)
and resolved at the tool layer.

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

### 16.4 One document, one interpretation

A PSDL document describes **one canonical, present-day interpretation** of a
packet. When a later RFC reinterprets the same bit range (e.g. the IPv4 ToS
octet redefined as DSCP+ECN by RFC 2474/3168), the document MUST encode only the
current consensus layout as structure; the historical interpretation is folded
into provenance (`meta.rfc.updates`, §5.4) and per-value annotations (`values`,
§5.3), not expressed as a parallel layout. Authors MUST NOT use `switch` /
`optional` to carry multiple competing RFC interpretations of the same bits
purely for historical record. The `switch` / `optional` containers remain an
escape hatch only for the rare case where two interpretations are genuinely both
live on the wire and selectable from packet content.

**Enforcement level.** This `MUST NOT` is **authoring guidance, not a checked
validation rule**. There is no row for it in the §11.1 validation-error table,
and the reference validator does not detect it — "two competing historical
interpretations" versus "two interpretations genuinely both live on the wire"
has no operational test a validator can apply (both compile to identical
`switch`/`optional` structure). A document that violates this guidance is
therefore **accepted** by a conforming validator; the rule is enforced by review
and by lint/style tooling that MAY emit a non-normative advisory, not by
load-time rejection. Authors and reviewers are responsible for honouring it.
