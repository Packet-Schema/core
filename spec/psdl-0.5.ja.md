# PSDL 0.5 — Packet Schema Definition Language（日本語版）

ネットワークプロトコルのワイヤフォーマットを記述するための YAML ベースの言語。
機械可読な正式スキーマは `schemas/psdl-0.5.yaml` を参照。

---

## 1. ドキュメント構造

PSDL ドキュメントはパケット型 1 つを表す単一 YAML マッピングである。

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

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `name` | yes | パケット識別子（パケットセット内でグローバルに一意） |
| `body` | yes | コンテナの順序付きリスト |
| `version` | no | PSDL バージョン文字列（推奨。§15 参照） |
| `description` | no | 人間が読める要約 |
| `byteOrder` | no | デフォルトのバイトオーダー：`BE` または `LE`（デフォルト `BE`） |
| `rendererHints` | no | 表示専用メタデータ |
| `meta` | no | ツール用 RFC・エイリアスメタデータ |
| `abbrev` | no | プロトコルフィルタ名（Wireshark 等）。省略時は `name` と同じ |
| `constraints` | no | 逆伝播用等式制約 |
| `defs` | no | 再利用可能な名前付き struct 定義 |
| `imports` | no | クロスファイル def インポート（§1.2 参照） |

### 1.1 パケットメタデータ（`meta`）

```yaml
meta:
  rfc: 791          # RFC 番号（整数）
  section: "3.1"    # RFC セクション（文字列）
  aliases: [ip, ipv4]   # このパケット型の別名リスト
```

全フィールドは省略可能。codegen・Chrome extension・LSP による識別・相互参照に使用。

### 1.2 クロスファイルインポート（`imports`）

`imports` リストを使うと、他の PSDL ファイルの `defs` を名前空間プレフィックスで参照できる。
IPv4 アドレス構造体・MAC アドレス・TLS 拡張ヘッダ等の共通構造を
copy-paste せずに複数ファイルで共有するための仕組み。

```yaml
imports:
  - source: common/addresses.psdl
    as: addr
  - source: "@packet-schema/presets/tls-types"
    as: tls
```

インポート後は名前空間プレフィックスを使って参照できる：`ref: addr.ipv4Addr`。
展開後の id も同じドットルールに従う：`addr.ipv4Addr.oct0`。

**ルール：**

- `source` は不透明なパス文字列。解決戦略（ファイルシステムパス・パッケージレジストリ・URL）
  はツールレイヤの責務。
- `as` で名前空間プレフィックスを定義する。`[a-zA-Z][a-zA-Z0-9_]*` に一致する必要がある。
- 同じ `as` プレフィックスを持つ 2 つのインポートは検証エラー。
- 循環インポート（A が B をインポートし B が A をインポート）は検証エラー。
- インポートした def は読み取り専用。`imports` エントリですでに導入された名前を `defs` キーまたは別のインポートで再宣言することは検証エラー。
- `source` が解決できない場合は検証エラー。
- **インポートは再エクスポートされない。** あるドキュメントは、自身の `imports` に直接列挙したファイルで宣言された def のみ参照できる。ファイル B がプレフィックス `c` として C をインポートしている場合でも、A が B をインポートした後にそのプレフィックスは A から**見えない**。A が C の def を必要とする場合、A 自身の `imports` に C を明示的に列挙しなければならない。直接列挙していないインポート（推移的インポートのみを通じて解決される）の `ref` ターゲットは検証エラー。

### 1.3 インポート名の可視性

インポートされた def 名が式・`checksumCovers`・`constraints` でどのように見えるかを
以下のルールが規定する：

- `body` 内で `ref` コンテナの id として使われたインポート def 名は、フィールドをインポート
  プレフィックスではなく**インスタンス化 id** のもとにローカル名前空間へ展開する。たとえば
  `ref: addr.ipv4Addr` かつ `id: src` の場合、`src.oct0`・`src.oct1` 等に展開される
  （`addr.ipv4Addr.oct0` ではない）。
- `checksumCovers` はローカルのインスタンス化 id（例：`src`）とドット付きリーフ id（例：`src.oct0`）
  の両方を受け入れる。def がインポート由来かローカル `defs` 宣言かは問わない。
- インポート修飾 def 名（例：`addr.ipv4Addr`）を `checksumCovers` に直接記述することは検証エラー。
  代わりにインスタンス化 id（例：`src`）またはそのドット付きリーフ形式（例：`src.oct0`）を使用すること。
- constraint 式は、インポート由来のフィールドも含め、展開後の id で到達できる任意のフィールドを
  インスタンス化プレフィックス形式（例：`src.oct0`）で参照できる。

---

## 2. フィールド識別子

フィールドの `id` は式・クロスリファレンス・プロトコルリンキングで使う主要なハンドル。

- 作成者が記述できる文字：`[a-zA-Z][a-zA-Z0-9_-]*`
- `.` は ref 展開セパレータとして**予約済み**。id の中に使用不可。
- ref 展開後、`{ref.id}.{field.id}` の形式の仮想 id が生成される。
  これらのドット形式は式や `checksumCovers` で使用するが、YAML 内で直接記述することはない。
- インポート名前空間プレフィックス（§1.2）もドットで修飾：`addr.ipv4Addr`。
- id はその可視スコープ内（§10.1 参照）で一意でなければならない。

---

## 3. ワイヤ型

すべての `Field` はワイヤ上のビットを値にマップする `type` を持つ。

### `int` — 固定幅整数

```yaml
type: { kind: int, bits: 16 }              # 符号なし 16 ビット
type: { kind: int, bits: 8, signed: true } # 符号あり 8 ビット
```

### `bits` — 生ビットフィールド

数値的意味なし。フラググループやパディングに使用。
バイト幅が整数（n が 8 の倍数かつ 8 超）**かつ**バイト境界から始まる `bits` フィールドは、
マルチバイト読み取り時にパケットレベルの `byteOrder` に従う。それ以外の幅の `bits` フィールド、
またはバイトの途中で始まる/終わるフィールドは、バイトオーダースワップのない生の MSB-first
ビット列である（§12 の完全なバイトオーダー規則と `int`/`enum` との区別を参照）。

```yaml
type: { kind: bits, n: 3 }
```

### `bytes` — 可変長バイト配列

長さは式で指定（結果はバイト数）。式が `0` の場合、フィールドは 0 バイトを占める。

直接の囲むスコープ提供コンテナ（`bounded` スコープ・`encrypted.plaintext` struct・
トップレベル `body`）の残りすべてのバイトを消費するには `n: { kind: remaining }`（§4）を
使用する。リージョン末尾に末尾アンカーフィールド用の固定バイト数を残すには、データフィールドを
`remaining - <constByteCount>` でサイズ指定し、末尾アンカーフィールドをその後ろに通常の
フィールドとして配置する。`remaining` プリミティブは、スコープ内の任意の位置 — スコープ中間・
最後の位置・`cond` などの複合式の中 — で `bytes.n` に使用できる（データ消費コンテナの定義と
位置ルールは §4 を参照）。

```yaml
type: { kind: bytes, n: { kind: ref, field: length } }
type: { kind: bytes, n: { kind: remaining } }  # 囲むスコープの残りすべてのバイト
```

`bytes` フィールドは `display` ヒント（§14）を持つことができ、表示レイヤのツールに
ペイロードの描画方法を伝える：テキスト（HTTP リクエストライン・SIP・DNS ラベル）には
`ascii`/`utf8`、構造化アドレス（MAC・IPv6）には `addr`、不透明なブロブにはデフォルトの
`hex`。これは**表示専用**でワイヤセマンティクスを持たない（`bytes` はこのヒントに関わらず
同一にラウンドトリップする）。

> **ネーム圧縮ポインタ（対象範囲外）。** ネーム圧縮ポインタ（DNS RFC 1035 §4.1.4・
> NBNS・mDNS）は、ワイヤレベルでは 2 バイトのポインタフィールドとして表現でき、先頭 2
> ビット（値 `11`）への `peek` でラベルと区別し、下位 14 ビットをオフセットとして読み取る。
> しかし、その絶対オフセットを**逆参照（解決）**して論理名を再構築すること — 任意の
> （通常は後方の）メッセージオフセットへジャンプし、そこでパーサに再入して可変長ラベル
> シーケンスを読み取ること — は PSDL の**対象範囲外**であり、コーデック/ツールレイヤの
> 関心事である。PSDL の位置プリミティブは前方専用かつ相対的である（`peek` は非消費かつ
> 有界、`remaining`/`enclosingBits` はアドレス指定可能な位置ではなくスコープバジェットを
> 与え、`align` は前方にのみ移動する）。絶対オフセットのランダムアクセスプリミティブは
> 存在せず、それを追加すると仕様の他の部分が依拠する前方専用パースモデルが損なわれる。
> これは §7 のプロトコルリンキング解決をツールレイヤに委ねることと並行する。

> **テンプレート定義のレコードレイアウト（対象範囲外）。** 一部のプロトコルは、レコードの
> フィールドレイアウトを、Data Record が実行時に参照する Template Record で定義する。この
> テンプレートは先行パケットで届くこともあれば、データの前に**同じ**パケットに同乗することも
> ある：IPFIX（RFC 7011）と NetFlow v9（RFC 3954）は、Template FlowSet とそれが記述する Data
> FlowSet を、テンプレートをデータより前に並べて 1 つの UDP パケットで運ぶことが多い（RTPS/DDS
> も同じクラス）。PSDL はテンプレート（`{ informationElementId, fieldLength }` エントリの
> `repeat`）を解析でき、データセットを不透明な `bytes` として解析できるが、データレコードを
> テンプレートが定義した**フィールドとして**解析することは**できない** — テンプレートが同じ
> body 内で先に解析される完全なパケット内ケースであっても。障害は**ランタイムに発見される
> フィールドレイアウトのインスタンス化**であって、セッション/クロスパケット状態ではない：
> データレコードのレイアウト（ランタイムに決まるアリティの幅のリスト）はテンプレートを解析する
> ことで発見されるが、解析済みの `{ id, len }` ペアを後続リージョンの**構造**に変えるプリミティブ
> が存在しない。`switch`/`lookup` は静的に宣言されたアームの中から値で 1 つを判別するのであって
> フィールドリストを合成するのではなく、`repeat` はテンプレートエントリを反復でき `bounded`
> スコープはデータセットを不透明なバイトとして囲い込めるが、いずれも解析済みエントリをデータ
> リージョンのスキーマとして束縛しない。再帰的 def や `imports` は静的に宣言された構造のみを
> 形作る。PSDL は単一の自己記述的なパケット型を記述するため、テンプレート定義の動的レコード
> レイアウトは**対象範囲外**であり、コーデック/ツールレイヤの関心事である — 上記の DNS
> 圧縮ポインタ逆参照と構造的に同じクラスである。

### `enum` — 名前付き列挙

キーは数値、値はラベル（オプションで doc 付き）。

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

### `varint` — 可変長整数

`encoding` は可変長整数エンコーディング方式の名前。以下の値が定義済みで、
**任意の文字列も受け入れる**（`checksumAlgorithm` と同様。カスタムエンコーディングはコーデックで実装）。
デコーダがその `encoding` 文字列を実装していない `varint` フィールドに遭遇した場合は
**ランタイムエラー**となる。後続のフィールドは解析できない。これは未知の `checksumAlgorithm`
よりも重篤な失敗であり、varint フィールドが消費したバイト数が不明なためストリームの
後続パース位置が不定になる。

| 値 | 説明 |
|----|------|
| `quic` | QUIC 可変長整数（RFC 9000 §16） |
| `protobuf` | Protocol Buffers varint（base-128、little-endian グループ） |
| `cbor` | CBOR 符号なし整数（major type 0） |
| `ea-terminated` | 拡張ビット方式：バイト LSB=0 が続きあり、LSB=1 が最終バイト（Frame Relay DLCI、LAPD） |
| `leb128` | 符号なし LEB128（WASM、DWARF） |

```yaml
type: { kind: varint, encoding: quic }
type: { kind: varint, encoding: ea-terminated }
type: { kind: varint, encoding: my-custom-scheme }
```

> **CoAP の option delta/length：** CoAP はセンチネル値（13、14、15）で 1 バイトまたは
> 2 バイトの拡張をトリガする 4 ビットニブルを使う。EA-bit 方式ではないため、
> 4 ビットニブルに対する `switch` と各拡張形式の `bytes` アームでモデル化する。

### `berLength` — BER 長さフィールド

ASN.1/TLS で使われる自己記述的な 1〜N バイトの長さフィールド。
オプションの `maxBytes` プロパティ（1〜5、デフォルト 5）はエンコードされた長さの最大値を制限する。
`maxBytes > 5` の宣言は検証エラー。`maxBytes` を超えるワイヤエンコード長の受信はランタイムエラー。

```yaml
type: { kind: berLength }
type: { kind: berLength, maxBytes: 3 }
```

> **不定長（BER/CER の 0x80）。** `berLength` は**確定（definite）**形式のみをモデル化する。
> 不定（indefinite）形式（長さオクテット `0x80`、内容は 2 バイトの `00 00` End-of-Contents
> マーカーで終端）に対して `berLength` が返す値は**未定義**であり、不定形式では `berLength`
> フィールドを `bytes.n` / `bounded.bytes` のソースとして使用してはならない（MUST NOT）。
> バイト数がないため、`bounded` スコープ（`bytes` を必要とする）は内容を境界付けできず、
> 再帰的 def の `count: eos` repeat には終端すべきスコープ境界が存在しない — 終端子は長さ由来の
> バジェットではなく EOC マーカーである。不定構造形式は既存のプリミティブを組み合わせて
> モデル化する：長さバイトを `peek` し、`0x80` に対して `switch` し、不定アームでは内容を
> `count.until` が `peek(8) == 0` である `repeat`（内容位置で本物の BER タグが `0x00` になることは
> ない；`0x00` は EOC の開始である）で再帰的な値要素にわたって解析し、その後 2 バイトの EOC を
> 末尾の固定フィールドとして消費する。不定長の値には §6 で ASN.1 向けに示した確定 `bounded`
> スコープの慣用句を使用しないこと。SNMP/LDAP は不定長を使用することがあり、CER（GOOSE/
> MMS-over-ASN.1 で使用）は構造型に対してこれを必須とする。

---

## 4. 式

式はフィールド長・repeat カウント・switch 判別子・optional 条件で使われる
純粋でシリアライズ可能な値。

### リテラル

```yaml
{ kind: lit, value: 20 }
```

式が期待される場所ではベア YAML 整数も使えるオーサリング省略形：

```yaml
count: 4          # { kind: lit, value: 4 } と等価
```

### フィールド参照

id でフィールドの値を参照する。body 式では現在のコンテナよりも前（§10.1）に
現れるフィールドのみ参照可能。`constraints` 式はこのルールを免除される。

```yaml
{ kind: ref, field: totalLength }
{ kind: ref, field: src.oct0 }   # ref 展開フィールド
```

有効な field-id に一致するベア YAML 文字列も省略形として使える：

```yaml
type: { kind: bytes, n: length }   # { kind: ref, field: length } と等価
count: recordCount
```

参照したフィールドがワイヤ上に**存在しない**場合、式は §10.2 のシード値か `0` を返す。

`field` が（リーフフィールドではなく）**`repeat` コンテナの `id`** である `ref` は、
その repeat の**完了イテレーション数**に評価される。これは §10.7 で規定される
`env[repeat.id]` 値を再利用する（§10.7 はデコーダがこの値を `count: eos` repeat だけでなく
固定カウント repeat についても設定することを要求する）。これにより、カウントフィールドが
通常の制約（`countField == <repeatId>`）を通じて既存の制約ソルバー（§9）でバックプロパ
ゲーションできる — これはバイト数ではなく要素数を返すことに注意。ワイヤバイトのフットプリント
には `wireSize`（後述）を使用する。繰り返し要素数に等しくなければならないカウントフィールド
（IPv4 オプション、DNS qdcount/ancount/nscount、BGP path-attribute カウント、TLV リスト）は、
要素が可変幅の場合は他の方法では表現できない。`wireSize` がカウントをバックソルブできるのは
すべての要素が固定幅の場合に限られるためである。

body 式では、repeat コンテナの `id` への `ref` はリーフ `ref` とまったく同様に §10.1 の
前方参照ルールの対象である：repeat コンテナはドキュメント順でその式より前になければならない。
シード注入された `env[repeat.id]`（§10.7）は、その値を constraints（前方参照を免除される）と、
repeat より**後ろ**に置かれた body 式で利用可能にする。ドキュメント順で repeat より**前**に
ある body 式から repeat の id を参照することは検証エラー（§11.1）。`eos` repeat のシードされた
カウントは Parse の前から利用可能であるのに対し、固定カウント repeat のカウントはその先行する
カウントフィールドがパースされて初めて判明する点に注意。

### 二項演算

```yaml
{ kind: op, op: "+", a: { kind: ref, field: a }, b: { kind: lit, value: 8 } }
```

利用可能な演算子：

| 演算子 | 説明 | 備考 |
|--------|------|------|
| `+` `-` `*` `/` `%` | 算術 | `/` はゼロ方向切り捨て；ゼロ除算・剰余はランタイムエラー |
| `<<` `>>` | シフト | 算術右シフト；32 ビット整数で演算 |
| `==` `!=` `<` `<=` `>` `>=` | 比較 | 結果は `0` または `1` |
| `&` `\|` `^` | ビット AND / OR / XOR | 32 ビット整数で演算 |

### 条件式（三項）

`test ≠ 0` なら `t` を、そうでなければ `f` を評価する。

```yaml
kind: cond
test: { kind: op, op: "==", a: { kind: ref, field: version }, b: { kind: lit, value: 4 } }
t: { kind: lit, value: 1 }
f: { kind: lit, value: 0 }
```

### テーブル参照

キー式を離散的なルックアップテーブルで値にマップする。CAN FD の DLC→バイト数変換など、
算術式で表現できない非線形マッピングに有用。キーがテーブルにない場合は `0`（サイレント）。

**キー型ルール：** テーブルキーは非負の 10 進数整数リテラルでなければならない。
負のキーはサポートしない（負の判別子はルックアップ前に `cond` 式で処理すること）。
キー式の結果はルックアップ前にゼロ方向の整数に切り捨てられる（`/` 演算子と同じルール）。
切り捨て後の整数が負の場合はいかなるテーブルキーにも一致せず（全キーは非負）、結果は `0`（キー未発見と同じ）。
非負の 10 進数整数でない YAML テーブルキーは検証エラー。

**値型ルール：** テーブルの値は非負の 10 進数整数リテラルでなければならない。
非負の 10 進数整数でない YAML テーブル値は検証エラー。負または非整数の値は許可されない。
ルックアップ結果は `bytes.n` や `repeat.count` に渡されるため、非負整数が必要（§11.1 の対応する検証エラーを参照）。

```yaml
kind: lookup
key: { kind: ref, field: dlc }
table:
  0: 0
  1: 1
  9: 12    # DLC 9 → 12 データバイト
  10: 16
  11: 20
  12: 24
  13: 32
  14: 48
  15: 64
```

### Peek

現在のパース位置から `offset` ビット先の `bits` ビットを、消費せずに読み取る。
`offset` のデフォルトは `0`。

```yaml
{ kind: peek, bits: 8 }                               # 次のバイト
{ kind: peek, bits: 4, offset: { kind: lit, value: 4 } }
```

**ルール：**

- `peek` は `switch.on`・`optional.when`・`repeat.count`（`until` サブ式を含む）でのみ
  使用可能。`bytes.n` や `encrypted.wireBits` の中での使用は検証エラー。
- 各コンテキストでの「現在のパース位置」の定義は §10.6 を参照。
- peeked 領域が利用可能なデータを超える場合、結果は `0`。
- `peek` は未解析データを読み取ることができる唯一の式形式。

### バイト境界 repeat

「これまでに消費したビット数」専用のプリミティブも、repeat のバイト制限専用のプリミティブも
存在しない。指定バイト数の消費後に終端しなければならない repeat は、`count: eos` の repeat を
`bounded` スコープでラップして宣言的に表現する。この慣用句は §5（bounded スコープ）で
標準的に記述されている。

### 名前付き要素のワイヤサイズ（`wireSize`）

名前付きコンテナまたはフィールド（`target`）がワイヤ上で消費した総**バイト数**を返す
（コンテナの場合は再帰的にネストされた内容をすべて含む）。リーフフィールドの場合はその
フィールドのワイヤフットプリント：固定幅型では `bits / 8` に等しく、`varint` および
`berLength` フィールドではエンコードサイズが可変となる。フィールドは名前付き要素のリーフ
ケースであるため、`wireSize` は per-field バイト数とコンテナ全体のバイト数の両方をカバーする。

```yaml
{ kind: wireSize, target: avpData }    # bounded/再帰コンテナの総バイト数
{ kind: wireSize, target: streamId }   # 単一フィールドのバイト数（QUIC varint なら 1/2/4/8）
```

**ルール：**

- `wireSize` は `constraints` 式、`Field` の `computedFrom` プロパティ、および body 式
  （§10.1 で列挙された位置）で、その `target` がドキュメント順で式より前に現れる場合に
  使用可能（`ref` と同じ前方参照ルール）。
- `target` が不在（optional が取られない・switch アームが選択されない・ref が展開されない）
  の場合、結果は `0`。直接の親が `optional` であるフィールドの場合は内側フィールドの `id`
  を（`optional` コンテナの id ではなく）ターゲットにする。その optional が不在の場合は `0`。
- ボトムアップ評価か前方評価かはコンテキストで決まり、別個のプリミティブによるものではない：
  body 式ではターゲットがパースされるにつれ前方に解決され、`constraints`/`computedFrom` では
  ネストされた内容の再帰的エンコード完了後に**ボトムアップ**で評価される。これにより
  コーデックは再帰構造で長さフィールドをバックプロパゲーションで充填できる。
- body 式では、`target` は式が評価される前に完全にパースされた（閉じた）コンテナまたは
  フィールドでなければならない — すなわちドキュメント順で式より前に現れ、**かつ**パース
  スタック上でまだ開いている祖先ではないこと。body 式で `target` がまだ閉じていない囲む/
  祖先コンテナである `wireSize` は検証エラーである。そのようなターゲットには
  `constraints`/`computedFrom`（ボトムアップ）でのみ使用すること。
- DECODE 時、制約または `computedFrom` 内の `wireSize: target` は、Parse フェーズ（§10.0）中に
  ターゲットがワイヤ上で実際に消費したバイト数に解決される。上記のボトムアップ評価が適用される
  のは SERIALIZE 時のみで、そこではネストされた内容が先にエンコードされ、そのサイズをボトム
  アップで合計してフィールドを充填する。

**`Field` の `computedFrom` プロパティ：**

`Field` にはオプションの `computedFrom` プロパティを持たせることができ、値は
`wireSize` 式となる。これはコーデックに対してフィールドを再帰的エンコード完了後に
計算・充填するよう明示的に指示する：

```yaml
- id: avpLength
  name: AVP Length
  type: { kind: int, bits: 24 }
  category: length
  computedFrom: { kind: wireSize, target: avpData }
```

`computedFrom` アノテーションはパースに影響しない（ワイヤ値は通常通り読み取られる）。
シリアライザへのヒントのみ。`wireSize` 以外の式で `computedFrom` を使用するのは検証エラー。

### 前イテレーションのフィールド参照（`prevIter`）

`repeat.count.until` 式の中でのみ使用可能。直近の囲む repeat の**最後に完了したイテレーション**
の名前付きフィールドの値を参照する。その唯一の目的は、前イテレーションに依存するループ終端
条件を表現することである。

```yaml
{ kind: prevIter, field: tsn }   # 前イテレーションの 'tsn' の値
```

**ルール：**

- `prevIter` は `repeat.count.until` 内でのみ有効。
- 最初のイテレーション（前のイテレーションが存在しない）では、`prevIter.field` は
  §10.2 のシード値、またはシードがない場合は `0` を返す。
- `repeat.count.until` 外での `prevIter` の使用は検証エラー。

> **イテレーション間の不変条件**（例：「SCTP DATA チャンクの TSN は厳密に増加しなければ
> ならない」）は PSDL では表現**しない**。per-iteration のアサーション機能は存在しない。
> そのような「式をチェックし、不一致で警告する」挙動は、§9 の制約（id で到達できるフィールド
> に対して）の役割であり、単調性などの制約モデルでは到達できない真にイテレーション間の
> チェックについてはコーデックレイヤの役割である — 非長さの per-instance 不変条件をコーデックに
> 委ねる §6 と一貫している。**イテレーション間の累積/アキュムレータ的な再構築**（例：CoAP
> オプションの絶対番号 = 先行するすべてのオプション delta の累積和）も同様に**対象範囲外**で
> あり、コーデック/ツールレイヤの関心事である。理由は同じで、`prevIter` は最後のイテレーションの
> 値のみを露出し、fold/アキュムレータプリミティブが存在しないためである。これは構造的な
> パースギャップではなく値再構築のギャップである — 各オプションのワイヤフットプリントは依然として
> 自身の delta/length ニブルのみに依存する（§3 の CoAP switch 慣用句）ため、後続のパースは影響を
> 受けない。materialize できないのは絶対オプション番号を `virtual` フィールドとして実体化する
> ことだけである。同じ形は任意の delta コードリスト（一部の TLV/オプションエンコーディング等）
> でも再帰的に現れる。

### 残りバイト数（`remaining`）

**スコープ提供コンテナ**とは、独立したワイヤカーソルのバジェットを確立するちょうど 3 つの
コンテナのいずれかである：`bounded` スコープ・`encrypted.plaintext` struct・トップレベル
`body`。それ以外のコンテナ（`group`、プレーンなインライン `struct`、`repeat`、`switch` アーム、
`optional`）はスコープを提供しない。`remaining`/`enclosingBits` および `count: eos` は、最も
近い囲むスコープ提供コンテナに対して解決される。

「直近の囲むスコープに残っているバイト数」を表す唯一のプリミティブ。`(スコープのバイト
バジェット) − (評価時点でそのスコープ内で消費済みのバイト数)` に解決される。ここで囲む
スコープとは最も近いスコープ提供コンテナである。これは旧 `remainingBytes`・
`scopeRemainingBytes`・`enclosingBytes`・`totalPacketBytes` プリミティブを置き換える。
これらはすべて同じ値を計算しており、スコープの種類が異なるだけだった。

```yaml
# 残りのオプションバイトを生のブロブとして消費する（スコープ中間での使用も許可）
type: { kind: bytes, n: { kind: remaining } }

# 最後の 2 バイトを除いてプレーンテキストバイトをすべて消費（末尾アンカーフィールドが後続する）
type: { kind: bytes, n: { kind: op, op: "-", a: { kind: remaining }, b: { kind: lit, value: 2 } } }

# QUIC STREAM：LEN=1 のとき Length を使用し、そうでなければ残りすべてのバイトを消費
n:
  kind: cond
  test: { kind: ref, field: lenBit }
  t: { kind: ref, field: length }
  f: { kind: remaining }
```

**ルール：**

- `remaining` は `bytes.n`、およびスコープ提供コンテナ内の他の任意の body 式で有効。
  その後ろにいくつのデータ消費コンテナが続くかに関わらず、任意の位置に現れてよい — スコープ
  中間・最後の位置・`cond` の中。（**データ消費**コンテナとは、ワイヤカーソルを進めるもの：
  非ゼロ幅型の `Field`、`bytes` フィールド、`repeat`、`bounded` スコープ、`encrypted` リージョン、
  選択された `switch` アーム、または `align` パディング。`virtual` フィールドと非選択の switch
  アームは何も消費しない。）
- スコープ提供コンテナの外では定義されたバジェットが存在しない。そこで `remaining` を使う
  のは検証エラー。
- トップレベル `body` のスコープバジェットは**デコーダが注入する総パケットバイト数**である。
  したがってトップレベル `body` 式中の `remaining` は、デコーダが総パケットサイズを注入する
  こと（例：リンクレイヤから）を必要とする。総数が注入されない場合（外部から長さを与えずに
  生バッファをパースする場合）、トップレベル body での `remaining` には定義されたバジェットが
  なく、**ランタイムエラー**となる（パースストリーム位置を有界化できない）。`bounded` スコープ
  と `encrypted.plaintext` リージョンは常に定義されたバジェットを持つ（それぞれ bounded の
  `bytes` 式と `wireBits` バジェット）ため、これらの内部では `remaining` は常に意味を持つ。
- スコープの「絶対バジェット」は `(消費済みバイト数) + remaining`。絶対バイト総数が
  真に必要な場合は該当する長さフィールドを直接参照すること。ビット精度が必要な場合は
  下記の `enclosingBits` を使用すること。
- **サブバイトの丸め。** 「消費済みバイト数」は `ceil(スコープ内で消費したビット数 / 8)`
  として測定される — 部分的に消費されたバイトは完全に消費されたものとして数える（§5 の
  `align` 切り上げルールに一致）。その結果、`remaining` がカーソルがバイトアライメント
  されているときにのみ `bytes` フィールドのサイズ指定に対して明確に定義される。バイトの途中
  （mid-byte）で `remaining` を使ってデータをサイズ指定するのは**ランタイムエラー**である。
  最後の `bytes` フィールドはバイト境界の後にのみサイズ指定すること（先行するサブバイト
  フィールドがカーソルを途中に残した場合は先に `align` を挿入する）、あるいはサブバイト
  リージョンには `enclosingBits` の算術を使用すること。

  ワークド例：4 バイトの `bounded` スコープ（入場時 `remaining` = 4）が、12 ビットの `bits`
  フィールド、続いて `align to: 16`、続いて `count: eos` repeat を含むとする。`bits` フィールドは
  カーソルをビット 12（mid-byte）に残す。`align` はまず 12 を 16 ビットに切り上げ
  （`bytePosition = ceil(12/8) = 2`。これはすでに `16/8 = 2` の倍数なので追加パディングは 0
  バイト）、切り上げを計上してバジェットの 2 バイトが消費済みとなる。その後 `count: eos`
  repeat は残り `4 - 2 = 2` バイト内でパースする。`align` の**前**にカーソルがビット 12 に
  ある状態で `remaining` を評価するのはランタイムエラー（mid-byte）となる。

### スコープのビットバジェット（`enclosingBits`）

**ビットバジェットを持つ最も近いスコープ提供コンテナの注入された絶対ビットバジェット**を表す
唯一のプリミティブ。`remaining` と対をなすが、残りバイト数ではなくスコープの総ビット
バジェットを返す。注入されたビットバジェットを持つスコープ提供コンテナは次の 2 つ：

- `encrypted.plaintext` struct — `enclosingBits` は、暗号化コンテナがパース中に入られたときに
  評価される、囲む `encrypted` コンテナの `wireBits` 式の結果に等しい；
- **トップレベル `body`** — `enclosingBits` は外部（リンクレイヤ等）からデコーダが注入した
  総パケットビット数。

（`bounded` スコープのバジェットはバイト単位で記述されビット単位で注入されないため、
`enclosingBits` を提供しない。）この 2 つのケースは評価フェーズと前方参照の扱いが異なる
（§10.1 参照）：トップレベル `body` では、`enclosingBits` はパース前から利用できるデコーダ
注入の定数であり、前方参照制限の**例外**である。一方 `encrypted.plaintext` 内では、囲む
`wireBits` 式からパース中に計算され、通常の前方参照ルールの**対象**である（`wireBits` を
裏付けるフィールドは `encrypted` コンテナより前になければならない）。これは旧来のスコープ別
ビットバジェットプリミティブ（暗号化スコープのバジェットと `totalPacketBits`）を単一の
`enclosingBits` に統合したものである。これらは同じビットバジェットを計算しており、スコープの
種類が異なるだけだった。バイト境界が必要な場合は作者が `enclosingBits / 8` と記述する。

```yaml
# ビットバジェットから導出したバイト境界（サブバイト対応）。
# encrypted.plaintext struct またはトップレベル body 内で使用
type: { kind: bytes, n: { kind: op, op: "/", a: { kind: enclosingBits }, b: { kind: lit, value: 8 } } }
```

**ルール：**

- `enclosingBits` は `encrypted.plaintext` struct またはトップレベル `body` 内でのみ有効。
  ビットバジェットを持つスコープ提供コンテナの外（例：`bounded` スコープや
  ネストされた非スコープ `struct` の中）での使用は検証エラー。
- トップレベル `body` では、`enclosingBits` はデコーダ注入の定数であり、デコーダが総パケット
  サイズを注入することを必要とする。総数が注入されない場合は定義されたバジェットがない
  （トップレベル body での `remaining` と同じ注入要件）。また前方参照ルールの例外である。
- `encrypted.plaintext` 内では、`enclosingBits` は囲む `encrypted` コンテナの `wireBits` に
  等しく、前方参照ルール（§10.1）の対象である：その `wireBits` 式が参照するすべてのフィールドは
  ドキュメント順で `encrypted` コンテナより前になければならない。`encrypted` コンテナが
  `wireBits` を省略した場合、plaintext には定義されたビットバジェットがなく、そこでの
  `enclosingBits` は検証エラー（§5 Encrypted、§11.1）。
- パケットのどのフィールドにもビット精度のサイズが格納されていない場合に有用。総長
  フィールドが存在する場合はそれを直接参照することを推奨する。バイトアライメントされた
  総数には `remaining` を推奨する。

### クロスレイヤフィールド参照（`enclosingField`）

直接囲むプロトコルレイヤの解析済み状態から名前付きフィールドを参照する。

```yaml
{ kind: enclosingField, field: protocolType }
```

`enclosingField` は `constraints` で**のみ**有効。body 式での使用は検証エラー（§11.1）。
これはコーデックが供給する別個の囲むレイヤの env から読み取り、囲むレイヤが存在しない場合は
`0` を返す。完全なセマンティクスは §7（クロスレイヤフィールドアクセス）、囲むレイヤの env が
利用可能になるフェーズは §10.0 を参照。

---

## 5. コンテナ

### Field

基本単位。`kind` は省略可能。

```yaml
- id: srcPort
  name: Source Port
  type: { kind: int, bits: 16 }
  category: addressing
  doc: 送信元ポート番号
  byteOrder: BE
  display: dec
  meta:
    rfc: 793
    section: "3.1"
```

全プロパティ一覧：

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `id` | yes | 式で使う識別子 |
| `name` | yes | 人間が読めるラベル |
| `type` | yes | ワイヤ型 |
| `kind` | no | 存在する場合 `"field"` でなければならない |
| `doc` | no | 説明文字列 |
| `meta` | no | フィールドレベルの RFC アノテーション `{ rfc?, section? }` |
| `category` | no | 意味カテゴリトークン（§5.1 参照） |
| `const` | no | このフィールドが持つべき固定値（§5.2 参照） |
| `defaultValue` | no | フィールドが存在しない場合の env シード値 |
| `byteOrder` | no | フィールドレベルのバイトオーダーオーバーライド（`int`/`enum` のみ） |
| `display` | no | 表示ヒント：数値の `hex`、`dec`、`oct`、`bin`（デフォルト `dec`）。`bytes` フィールドでは加えて `ascii`、`utf8`、`addr`（デフォルト `hex`）。表示専用（§14 参照） |
| `next` | no | プロトコルリンキングマップ（§7 参照） |
| `checksumAlgorithm` | no | チェックサムアルゴリズム（§8 参照） |
| `checksumCovers` | no | このチェックサムが対象とするフィールド（§8 参照） |
| `checksumPseudoHeader` | no | 付加する既知の擬似ヘッダ（§8 参照） |
| `checksumParams` | no | CRC バリアントのアルゴリズムパラメータ（§8 参照） |

#### 5.1 カテゴリトークン

| トークン | 意味 |
|---------|------|
| `addressing` | 送信元または宛先アドレス |
| `identifier` | バージョン、タイプ、プロトコル番号 |
| `length` | 長さ・サイズフィールド |
| `type` | タイプ・種別判別子 |
| `flags` | ブール型フラグビット |
| `reserved` | 将来用/ゼロ必須 |
| `checksum` | 整合性チェック値 |
| `variable` | ペイロードまたは汎用可変データ |
| `payload-marker` | 上位レイヤペイロードの開始を示す |

#### 5.2 `const`

このフィールドが固定値を持つことを宣言する。不一致はパース時のランタイムエラー。
`const` は env シードにも使われる（§10.2 参照）。`defaultValue` も指定されている場合は
`const` が優先される。

```yaml
- id: version
  name: Version
  type: { kind: int, bits: 4 }
  const: 4
  category: identifier
```

### Ref（struct インスタンス化）

`ref` コンテナは `defs` の struct を `body` にインスタンス化する。これはパーサが判別する
body コンテナ種別の 1 つである（field・group・optional・repeat・switch・align・bounded・
encrypted と並ぶ）。

```yaml
- kind: ref
  ref: ipv4Addr
  id: src
  name: Source Address
```

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"ref"` |
| `ref` | yes | ターゲット def 名（ローカル `defs` キーまたはインポート修飾、§1.2） |
| `id` | yes | インスタンス化 id；展開後のフィールド id のプレフィックスになる |
| `name` | no | 人間が読めるラベル |
| `doc` | no | LSP ホバー用の説明 |

展開ルール（透明なスコープ継承、`{ref.id}.{field.id}` および repeat インデックス付き
`{ref.id}.{field.id}#N` の id 形式）は §6 を参照。

### Virtual field

ワイヤバイトを**消費しない**計算補助フィールド。`expr` はパース時に body 式と同じ
前方参照ルール（§10.1）で評価され、その `id` は env に追加されて後続の body 式・
`constraints`・`checksumCovers` から参照できる。

```yaml
- kind: virtual
  id: offBit
  expr:
    kind: op
    op: "&"
    a: { kind: op, op: ">>", a: { kind: ref, field: type }, b: { kind: lit, value: 2 } }
    b: { kind: lit, value: 1 }
```

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"virtual"` |
| `id` | yes | 後続式で使う識別子 |
| `expr` | yes | パース時に評価される式 |
| `name` | no | 人間が読めるラベル |
| `doc` | no | 説明 |

**ルール：**

- `virtual` フィールドはワイヤビットをゼロ占有する。パース位置を進めない。
- `expr` は他の body 式と同じ前方参照ルールに従う：`virtual` フィールドよりも
  ドキュメント順で前に現れるフィールドのみ参照可能。
- `virtual` フィールドの id は `checksumCovers` で使用できるが、チェックサム入力に
  対してゼロバイトを貢献する（この文脈では表示専用メタデータ；代わりに元のソース
  フィールドを列挙することを推奨）。
- `virtual` フィールドは `defs` 内には配置できない（再帰コンテキストで評価順の
  問題を引き起こす可能性がある）。def 内への配置は検証エラー。

### Group

隣接するフィールドを 1 つのビジュアル行に折り畳む。
`doc` は LSP のホバードキュメントに使われる。
`meta` は Chrome extension のフィールドレベルディープリンクを可能にする。

```yaml
- kind: group
  id: flags
  name: Flags
  doc: TCP 制御ビット（RFC 793 §3.1）
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

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"group"` |
| `id` | yes | グループ識別子 |
| `name` | yes | 人間が読めるラベル |
| `children` | yes | コンテナの順序付きリスト |
| `doc` | no | LSP ホバー用の説明 |
| `meta` | no | グループレベルの RFC アノテーション `{ rfc?, section? }` |
| `category` | no | 意味カテゴリ（Field と同じトークン） |

### Optional

コンテナを条件付きで含める。`when` はブール値として評価：`0` = 不在、非ゼロ = 存在。

`optional` を別の `optional` の中にネストすることが**できる**。
内側の `when` は外側の optional が存在する場合にのみ評価される（ショートサーキット評価）。
外側が不在の場合、内側コンテナは `when` を評価せずに不在として扱われる。
任意のネスト深さに適用される。§10.8 を参照。

コンテナが不在の場合、その全フィールドは後続式で参照されたとき §10.2 のシード値を返す。

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
      - kind: optional   # ネストされた optional — 許可
        when: { kind: op, op: "==", a: { kind: ref, field: kind }, b: { kind: lit, value: 8 } }
        container:
          id: timestamp
          name: Timestamp
          type: { kind: int, bits: 32 }
```

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"optional"` |
| `when` | yes | ブール式（`0` = 不在、非ゼロ = 存在） |
| `container` | yes | 条件付きで含められるコンテナ |
| `id` | no | オプションの識別子。コンテナを `rendererHints.sections` エントリ（§13）に割り当て、`wireSize`（§4）の `target` にもできる。`wireSize` では optional の `id` ではなく内側フィールドの `id` をターゲットにすること。不在の optional は `0` を返す |
| `doc` | no | LSP ホバー用の説明 |
| `meta` | no | per-region ディープリンク用の RFC アノテーション `{ rfc?, section? }` |

### Repeat

struct 要素を繰り返す。

```yaml
# 固定カウント
- kind: repeat
  id: records
  count: { kind: ref, field: recordCount }
  element:
    id: record
    fields:
      - id: type
        name: Type
        type: { kind: int, bits: 8 }

# ストリーム末まで（デコーダが env[repeat.id] に反復回数を注入）
- kind: repeat
  id: entries
  count: eos
  element:
    id: entry
    fields:
      - id: value
        name: Value
        type: { kind: int, bits: 32 }

# sentinel まで：フィールドが 0 に等しくなったら停止
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

# N バイト消費まで：repeat を count: eos の bounded スコープでラップする。
# 標準的なバイト境界の例は §5（bounded スコープ）を参照。
```

**Repeat スコープ：** 同じイテレーション内の現在のフィールドよりも前に現れたフィールドのみ参照可能。
前のイテレーションのフィールドは `ref` では参照不可（`prevIter`（§4）を除く）。`until` は
各要素の完全解析後に評価され、現在のイテレーションの任意のフィールドを参照できる。
バイト境界の反復には、repeat を `count: eos` の `bounded` スコープでラップすること
（§5 bounded スコープ参照）。

repeat の `element` は §6 Struct 形式（`{ id, fields }`）に従うインライン struct であり、
したがって `doc`（LSP ホバー用）および `meta { rfc?, section? }`（per-region RFC ディープ
リンク用）も持つことができる。

**`eos` repeat：** end-of-stream の検出はデコーダ固有。**シード**フェーズ（§10.0）中に、
デコーダは `env[repeat.id]` にイテレーション数を注入しなければならない（MUST）。
キーが存在しない場合、正規化フェーズはデフォルトで `0` イテレーションとする。

### Switch

判別式に基づいて 1 つの struct アームを選択する。

**ケースキー形式：**

| 形式 | 例 | 意味 |
|------|-----|------|
| 10 進数文字列 | `"6"` | 完全一致 |
| 範囲 | `"0-127"` | 両端を含む閉区間 |
| リスト | `"6,17,58"` | 複数の完全一致値 → 同じアーム |
| デフォルト | `"_"` | キャッチオール |

**キー評価順序：** 所与の判別子値に対し、キーは（1）完全一致、（2）リスト所属、（3）範囲内、
（4）`"_"` の順でテストし、最初に一致したキーが勝つ。複数の範囲キーが一致しうる場合は、
ドキュメント順で**最初**に一致する範囲キーが勝つ。

判別子値はマッチング前にゼロ方向の整数に切り捨てられる（`/` 演算子および `lookup` キーの
ルールと同じ）。どのキーにも一致しない場合（どのキーにも `_` にも一致しない負の値を含む）、
switch は下記の空 struct ルールに従ってゼロバイトを消費する。範囲キーとリストキーは非負の
10 進数整数であり、負の値の境界は検証エラーである。

```yaml
- kind: switch
  id: payload
  on: { kind: ref, field: protocol }
  cases:
    "6":    { id: tcp,     fields: [...] }
    "17,136": { id: udp,   fields: [...] }
    "0-9":  { id: raw09,   fields: [...] }
    _:      { id: unknown, fields: [...] }
```

> **注意：** `_` キーは `cases` マップの中に記述する。`default` という別プロパティは存在しない。

非選択アームのフィールドは env に追加されない。後続の body 式で参照すると §10.2 の
シード値か `0` が返る。constraints からの参照はサイレントスキップ。

どのケースにも `_` にも一致しない場合はゼロバイト消費（エラーではない）。

各ケースアームは §6 Struct 形式（`{ id, fields }`）に従うインライン struct であり、したがって
`doc`（LSP ホバー用）および `meta { rfc?, section? }`（per-region RFC ディープリンク用）も
持つことができる。

### アライメントパディング（`align`）

現在のパース位置を指定したビット境界にアライメントするために、0 バイト以上を消費する。
`id` は不要（コンテナは env に名前付きフィールドを追加しない）。

```yaml
- kind: align
  to: 32     # 次の 4 バイト境界にアライメントするために 0〜3 バイトのパディングを消費
```

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"align"` |
| `to` | yes | アライメント対象（**ビット**単位の正の 2 のべき乗整数であり、かつ 8 の倍数。すなわち 8、16、32、64、…） |
| `fill` | no | シリアライズ時にパディングバイトを充填するバイト値（0〜255）（デフォルト：未指定/デコーダ定義） |
| `id` | no | パディングバイトを参照する必要がある場合のオプション識別子 |
| `doc` | no | 説明 |

**ルール：**

- アライメントの基準点は**ワイヤ/パケットバイトストリームの絶対原点**（トップレベル
  パケットの最初のビット）。下記の `position` はその絶対原点から測った現在のパース位置の
  ビット数。囲むスコープの開始位置ではなく絶対原点を使うことで、囲むスコープ提供コンテナ
  自体が `to` の倍数で始まらない場合（例：任意のオフセットで始まる Grouped-AVP の `bounded`
  スコープ）でも `align` が真のワイヤ境界に着地することを保証する。これは SCTP/Diameter の
  チャンクアライメントのワイヤ絶対パディング意図（§8）と一致する。
- `to` は 8 の倍数に制限されるが、直前のサブバイト `bits` フィールド（またはビット幅の
  `int`/`enum`、§3）、あるいは生の MSB-first ビット列として読まれる幅広 `bits` フィールド
  （§12）は、カーソルをバイトの途中に残す可能性がある。したがって `align` は**まず現在の
  ビット位置を次の完全なバイトに切り上げ**、その後 `to` 境界へ進める。この切り上げは生の
  ビット位置に対して定義され、バイトオーダースワップを伴わない。`bytePosition =
  ceil(position / 8)`（部分バイトを切り上げた後のバイトオフセット）と定義する。
  `bytePosition` がすでに `to/8` の倍数であれば追加のパディングバイトは消費しない。
  そうでなければ消費するパディングバイト数は `(to/8 - (bytePosition % (to/8))) % (to/8)`
  に等しい。`align` が消費する総バイト数には部分バイトの切り上げ分も含まれ、カーソルは
  絶対原点から `to` ビットの倍数の位置で終わる。
- **`bounded` スコープ内**では、`align` が消費するパディングバイトは**スコープのバイト
  バジェットに対して計上される** — データバイトとまったく同様にスコープカーソルを進める —
  たとえそれらが対象とする境界がスコープ開始ではなく絶対ワイヤ原点から測られていても。
  したがって後続の `count: eos` repeat や `remaining` はそれらのパディングバイトを消費済みと
  見なす。計算されたパディングがスコープの残りバイトバジェットを超える場合、`align` は
  **ランタイムエラー**となる。

  ワークド例：絶対バイトオフセット 6 から始まる 10 バイトの `bounded` スコープが、1 バイトの
  フィールド（カーソルは絶対オフセット 7、10 バイトバジェットのうち 1 バイト消費）に続いて
  `align to: 32` を含むとする。絶対原点から次の 4 バイト境界はオフセット 8 なので、align は
  `(4 - (7 % 4)) % 4 = 1` パディングバイトを消費する。その 1 バイトはスコープバジェットに
  計上され、10 バイトのうち 8 バイトが残る。後続の `count: eos` repeat はその残り 8 バイト内で
  パースする。
- トップレベル `body`（または任意のスコープ）では、計算されたパディングが注入された
  データ末尾を超える場合、`align` は実際に利用可能なバイトのみを消費し、エラーには**ならない**
  — スコープ/パケット末でキャップされる。これは例えば SCTP のチャンクフレーミング
  （RFC 4960 §3.2）をカバーする。SCTP ではすべてのチャンクが 4 バイト境界にパディングされるが、
  パケットの最後のチャンクだけは末尾パディングを省略してよい（MAY）：最後のイテレーションでは
  カーソルが、切り上げ後のパディングバイト数より少ないバイトしか存在しない状態で注入された
  末尾にすでに位置している可能性があり、`align` は残っているものを単に消費する。（上記の
  `bounded` スコープ内ルールとは対照的である。そこでは宣言されたバイトバジェットを超える
  パディングはランタイムエラーとなる：`bounded` スコープのバジェットは作者が記述したもので
  あり、注入されたデータ末尾ではない。）
- アライメントパディングバイトは、`align` コンテナの `id` が `checksumCovers` に
  明示的にリストされていない限り、囲むチェックサム対象から**除外**される。
- `to` は 8 の倍数である正の 2 のべき乗整数でなければならず、それ以外の値は検証エラー。
- `fill` はシリアライズ時にパディングバイトに書き込むバイト値を指定する。
  省略時はフィル値はデコーダ/エンコーダ定義。指定する場合、デコーダに受信パディングバイトが
  `fill` と等しいか検証するよう指示する。不一致は検証警告（§11.3 の constraint-mismatch
  挙動に準じる）。`fill` は 0〜255 の整数でなければならず、それ以外は検証エラー。
  例：`{ kind: align, to: 32, fill: 0x00 }`（SCTP / Diameter のゼロ充填）。

### bounded スコープ

宣言されたバイト数（式で導出）に解析を制限するサブストリームカーソルを作成する。
これにより再帰的 def（またはネストされたコンテキスト）内の `count: eos` が
パケット末ではなくスコープ境界で終端できる。
長さ区切りの繰り返し構造体リスト（Diameter の Grouped AVP、802.11 の sub-IE 等）を
解析するための仕組みである。

これは**標準的なバイト境界 repeat** の慣用句である：`count: eos` の `repeat` をラップする
`bounded` スコープが、指定バイト数の消費後に repeat を終端する唯一の直交した方法である
（repeat のバイト制限専用のプリミティブは存在しない）。式の中で「現在のスコープで消費済み」の
値が必要な場合は、別個の per-repeat アキュムレータを保持するのではなく
（スコープバジェット − `{ kind: remaining }`）として導出すること。

```yaml
- kind: bounded
  id: avpData
  bytes: { kind: op, op: "-", a: { kind: ref, field: avpLength }, b: { kind: lit, value: 8 } }
  fields:
    - kind: repeat
      id: containedAvps
      count: eos        # パケット末ではなく bounded スコープ境界で終端
      element:
        id: avp
        fields:
          - id: avpCode
            name: AVP Code
            type: { kind: int, bits: 32 }
```

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"bounded"` |
| `id` | yes | スコープ識別子 |
| `bytes` | yes | このスコープのバイト数を与える式 |
| `fields` | yes | スコープ内で解析されるコンテナの順序付きリスト |
| `name` | no | 人間が読めるラベル |
| `doc` | no | 説明 |

**ルール：**

- `bytes` は他の body 式と同じ前方参照ルール（§10.1）で評価される。
- `bounded` スコープ内の `repeat` の `count: eos` は、スコープのバイトバジェットが
  尽きたときに終端する。より一般的には、`count: eos` repeat は最も近い囲むスコープ提供
  コンテナ — `bounded` スコープ・`encrypted.plaintext` struct（その `wireBits` バジェット）・
  トップレベル `body` — の境界で終端し、`bounded` スコープに限られない。これは
  `remaining`/`enclosingBits`（§4）が使うのと同じスコープ提供コンテナのリストである。
  したがって復号済みペイロードを埋めるフレームリスト（例：保護されたペイロード内の QUIC
  フレーム、RFC 9000 §12.4）は、`encrypted.plaintext` の直下の `count: eos` repeat であり、
  `bounded` スコープでラップするためのフィールド裏付けの長さは存在しない。
- `remaining` プリミティブ（§4）は、**直接の囲む** bounded スコープに対して解決される。
  `bounded` スコープはネスト可能で、それぞれが独立したバジェットを提供するため、
  ネストされたスコープ内の `remaining` はその内側スコープの残りバイトのみを消費し、
  外側スコープやトップレベル body は対象としない。
- `recursive: true` def 内の `bounded` スコープは、再帰的な各呼び出しサイトで
  `eos` repeat をスコープ境界に正しく閉じ込める。

### Encrypted

リージョンを暗号化済みとしてマークする。

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `kind` | yes | `"encrypted"` |
| `id` | yes | 暗号化コンテナの識別子 |
| `plaintext` | yes | 復号済みコンテンツを記述する struct |
| `wireBits` | no | 暗号化リージョンのサイズをビット単位で示す式 |
| `contextNote` | no | 暗号化リージョンツールチップに表示される人間可読メモ |
| `headerProtected` | no | plaintext 内のヘッダ保護フィールドの id リスト |
| `name` | no | 人間が読めるラベル |
| `category` | no | 意味カテゴリトークン |
| `doc` | no | 説明 |

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

`wireBits` が省略された場合、`encrypted.plaintext` struct には**定義されたバイトバジェットが
ない**：そのプレーンテキスト内の `remaining` と `enclosingBits` には定義された値がなく、それらの
使用は検証エラー（§11.1）となる。これはトップレベル `body` の「サイズ未注入」ルール（§4）と
並行する。プレーンテキストにバジェット依存の式が含まれる場合は常に `wireBits` を指定すること。

#### 末尾アンカーフィールド

一部のプロトコルは、タイプ判別フィールドや長さ判別フィールドを可変長リージョンの**末尾から
固定オフセット**の位置に置く（IPsec ESP Pad Length / Next Header）。PSDL には専用の末尾アンカー
コンテナはない：これらは `remaining - <constByteCount>` でサイズ指定された `bytes` フィールドの
**後ろ**に置かれた通常の固定幅フィールドとしてモデル化する。ここで `<constByteCount>` は末尾
アンカーフィールドの合計サイズ。データフィールドはそれらの末尾バイトを除くすべてを消費し、
末尾の固定幅フィールドが順に通常通りパースされ、ちょうどリージョン境界で終わる。この慣用句は
末尾フィールドが末尾から**固定**距離にあり、**かつ**いずれの末尾フィールドの値もそれより前の
フィールドのサイズを決定しない場合にのみ機能する（バックオフ距離 `<constByteCount>` は
ワイヤ値ではなくコンパイル時定数でなければならない）。これが除外する 2 つの対象範囲外の末尾
アンカーケースについては、下記の TLS 1.3 と RTP/SRTP のノートを参照。

```yaml
# IPsec ESP：復号済みペイロードの最後 2 バイト（Pad Length、Next Header）
- kind: encrypted
  id: espPayload
  contextNote: Encrypted with negotiated ESP cipher
  wireBits: { kind: op, op: "*", a: payloadLen, b: { kind: lit, value: 8 } }
  plaintext:
    id: espPlaintext
    fields:
      - id: data
        name: Payload Data
        # 末尾 2 バイトを除いてすべて消費
        type: { kind: bytes, n: { kind: op, op: "-", a: { kind: remaining }, b: { kind: lit, value: 2 } } }
      - id: padLength
        name: Pad Length
        type: { kind: int, bits: 8 }
      - id: nextHeader
        name: Next Header
        type: { kind: int, bits: 8 }
        category: identifier
```

> **TLS 1.3 inner-plaintext の content type（対象範囲外）。** TLS 1.3（RFC 8446 §5.4）は
> 実際のコンテンツの**後ろ**に任意の長さのゼロパディングを付加し、inner `ContentType` は末尾から
> 固定オフセットのバイトではなく**最後の非ゼロバイト**である。それを特定するには、リージョンの
> 末尾からゼロバイトをスキップしながら後方へスキャンする必要がある — 後方かつデータ依存の探索で
> ある。PSDL の位置プリミティブは前方専用かつ相対的である：`remaining`/`enclosingBits` は
> バジェットのみを与え、最後の非ゼロバイトの位置は与えない。`peek` は前方かつ有界であり、逆方向の
> 反復も「末尾から非ゼロまでスキャンする」構文も存在しない。前方の `repeat` は、末尾のコンテンツが
> どこにあるかを既に知っていなければ、ストリーム途中でゼロバイトが末尾パディングか実データかを
> 判別できない。上記の `remaining - <const>` の慣用句が機能するのは末尾オフセットが固定の場合のみで
> あり、TLS 1.3 はそうではない（パディング長がゼロの場合にのみ成立する）。したがって TLS 1.3 の
> inner content type の再構築は PSDL の**対象範囲外**であり — コーデック/ツールレイヤの関心事である —
> DNS ネーム圧縮ポインタの逆参照（§3）が対象範囲外であるのと同じ前方専用の理由による。後方スキャン
> プリミティブを追加すると、仕様の他の部分が依拠する前方専用パースモデルが損なわれる。

> **RTP/SRTP パディング（対象範囲外）。** P ビットがセットされた RTP（RFC 3550 §5.1）は、
> **最後のオクテットがパディングカウント**（自身を含む）であるパディングを付加する。ペイロードは
> `remaining - paddingCount` バイトを占め、続いて `paddingCount-1` バイトのパディング、続いて
> カウントオクテットが来る。上記の TLS 1.3 のケース（最後の非ゼロバイトを後方**スキャン**する）と
> 異なり、ここでは末尾アンカーオクテットは末尾から**固定**オフセット（1 バイト）に位置する — しかし
> その**値が先行するペイロードフィールドのサイズを決定**し、その値は前方パース順ではペイロードの
> **後**でしか読めない。これは `remaining - <constByteCount>` の慣用句が要求する**固定定数**の
> バックオフとは異なる**データ依存**のバックオフ距離である：`remaining - paddingCount` と書くと
> カウントオクテットがパースされる前にそれを参照することになる（前方参照違反、§10.1/§10.4）。
> `peek` はペイロードをサイズ指定できない（`switch.on`/`optional.when`/`repeat.count` に制限され、
> `bytes.n` では使えず、§11.1、かつ末尾相対ではなく前方相対である）。`remaining`/`enclosingBits`
> はバジェットのみを返し、末尾オクテットの値や位置を返さない。逆方向の反復・fold/アキュムレータ・
> 末尾相対アドレッシングのプリミティブは存在しない。したがって RTP/SRTP のペイロード境界の再構築は
> **対象範囲外**であり — コーデック/ツールレイヤの関心事である — 上記の TLS 1.3 inner-content-type
> ノートおよび DNS 圧縮ポインタ逆参照（§3）と同じ前方専用の理由による。末尾相対/後方アドレッシングを
> 追加すると、仕様の他の部分が依拠する前方専用パースモデルが損なわれる。

末尾アンカーフィールドは通常のフィールドである：後続の `constraints` から参照可能（例：データ
アライメントを検証する制約内で `padLength` を参照するなど）であり、囲むリージョンが
バイトアライメントされていることを要求する（`remaining - <const>` のデータサイズは整数バイトで
表現される）。サブバイトのリージョンは、明示的な `bits`/`bytes` フィールドと `enclosingBits` の
算術によってビットを明示的に消費すること。

---

## 6. Struct 定義と再利用

```yaml
defs:
  ipv4Addr:
    id: ipv4Addr
    doc: 4 オクテットで格納された 32 ビット IPv4 アドレス
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

展開後の id：`src.oct0`、`src.oct1`、…、`dst.oct0`、…

これらの仮想 id は式・`checksumCovers`・`next` ターゲットフィールド参照で使用できる。

**Struct プロパティ：**

| プロパティ | 必須 | 説明 |
|-----------|------|------|
| `id` | yes | Struct 識別子（`defs` のキーと一致） |
| `fields` | yes | コンテナの順序付きリスト |
| `doc` | no | LSP ホバーおよびツール用の説明 |
| `recursive` | no | `true` の場合、自己参照 struct が許可される（下記参照） |

**ルール：**

- `def` 内のフィールド id は `.` を含んではならない。
- 存在しない `defs` キーへの参照は検証エラー。
- `defs` 内の循環参照は、参照先の struct が `recursive: true` でない限り禁止。
- `def` 内フィールドの `defaultValue` は反映される。
- `def` 内フィールドの `const` はすべての展開インスタンスで強制される。
- `ref` は透明な展開：周囲のコンテナスコープを継承する。
- `repeat` 要素内では展開後の id が `{ref.id}.{field.id}#N` の形式になる（例：`src.oct0#2`）。
- スコープ順序：展開されたフィールドはドキュメント順で `ref` コンテナの位置から可視になる。
- 制約はドキュメントレベルのみで、単一の `def` インスタンス化にスコープできない。
  インスタンス化ごとの不変条件を表現するには、展開されたインスタンス化 id を参照する
  ドキュメントレベルの制約として追加すること。

### 再帰的 def

`recursive: true` を持つ `def` は自分自身または他の `recursive: true` def を指す
`ref` コンテナを含むことができる。デコーダが適切な深度制限を強制する責務を持つ。

```yaml
defs:
  asn1Value:
    id: asn1Value
    recursive: true
    doc: ASN.1 BER エンコード値（タグ・長さ・内容）
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
          "48":
            id: sequence
            fields:
              - kind: repeat
                id: children
                count: eos
                element:
                  id: item
                  fields:
                    - kind: ref
                      ref: asn1Value    # 再帰的自己参照
                      id: child
                      name: Child Value
          _:
            id: primitive
            fields:
              - id: value
                name: Value
                type: { kind: bytes, n: { kind: ref, field: len } }
```

**制限：**

- 再帰的 def は制約バックプロパゲーション（§9）ではサポートされない。制約ソルバーは
  再帰境界を解決不能な未知値として扱う。
- `lhs` または `rhs` が再帰的 def 展開内のフィールドを参照するドキュメントレベルの制約は
  （上記の例の `child.tag` など）、制約評価とバックプロパゲーションの両方で
  **常にサイレントスキップ**される。ハードな検証エラーではないが、ツールはロード時に
  lint 警告を発してその制約が評価されないことを作者に知らせるべき（SHOULD）。
  このルールは §9（参照フィールドが不在の場合に制約がスキップされる）と一貫している。
- 制約はドキュメントレベルのみで、単一の def インスタンス化にスコープできない。
  インスタンス化ごとの不変条件を表現するには、展開されたインスタンス化 id を参照する
  ドキュメントレベルの制約として追加すること。
- **インスタンスごとの長さ不変条件**（例：Diameter AVP-Length がその AVP の総ワイヤサイズに
  等しくなければならないなど）は、再帰的 def の PSDL 制約として表現できない。`bounded`
  スコープはバイトバジェットを制限することでパース時に長さを強制するため、推奨されるメカニズム。
  シリアライズ時は長さフィールドに `computedFrom: { kind: wireSize, target: id }`
  アノテーションを使用すること（§4 wireSize 参照）。これによりコーデックは再帰的エンコードの
  完了後にボトムアップでフィールドを計算・充填するよう明示的に指示される。
  このアノテーションがない場合、コーデックはプロシージャルにこれらの値を計算しなければならない。
- `encrypted` コンテナが再帰的 def 内で許可されるかどうか：各呼び出しサイト展開は
  新しい暗号化リージョンを作成し、各 `plaintext` 内の `remaining`/`enclosingBits` は
  その呼び出しサイトの `wireBits` にスコープされる（well-defined）。したがって `encrypted`
  コンテナは再帰的 def 内で**許可される**。

**制限と回避策：**

以下の制約型は再帰的 def では常に満たせず、コーデックでプロシージャルにチェックしなければならない：

1. **非長さのインスタンスごとの不変条件**（例：再帰レベルをまたいだタグ・値の整合ルール）—
   `bounded` スコープは長さの不変条件のみをカバーする。その他すべてのインスタンスごとのチェックは
   コーデックレイヤに委ねなければならない。
2. **バックプロパゲートされる長さフィールド** — 長さフィールドに
   `computedFrom: { kind: wireSize, target: id }`（§4 wireSize 参照）を使用して、
   再帰的エンコード後にボトムアップでフィールドを計算するようコーデックに指示すること。
   これがない場合、コーデックはプロシージャルにこれらの値を計算しなければならない。
3. **`lhs` または `rhs` が再帰的 def 展開内のフィールドを参照する制約** —
   常にサイレントスキップ（§9）。ツールは lint 警告を発する。このルールは推移的に適用される：
   再帰的 def の内部でインスタンス化された非再帰的 def も、コンストレイントソルバーが
   再帰境界を解決できないため、特定のフィールド参照では同じ constraint-skip 挙動を示す
   （その最も内側の def 自体が `recursive: true` かどうかに関わらず）。

---

## 7. プロトコルリンキング

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

**命名規則：** `next` マップの値は、ツールのアクティブなパケットレジストリに含まれる
ターゲット PSDL ドキュメントの `name` または `meta.aliases` のいずれかと一致すること（SHOULD）。
レジストリ間の名前衝突はツールレイヤが解決する。

`_` キーは `next` マップ内で有効で、「フィールド値にかかわらず常にこのプロトコルにリンクする」
を意味する。判別子なしに常に同じプロトコルのペイロードをモデル化する標準的な方法。
例（VXLAN inner Ethernet フレーム、RFC 7348）：

```yaml
- id: vni
  name: VNI
  type: { kind: int, bits: 24 }
- id: innerFrame
  name: Inner Frame
  type: { kind: bytes, n: { kind: remaining } }
  next:
    _: ethernet    # 常に Ethernet フレーム；型判別子なし
```

`next` マップはメタデータのみ。解決戦略はツールレイヤの責務で PSDL の関心事ではない。

**ハンドオフペイロードの特定。** `next` は値をターゲット名にマップするだけで、それ自体は
コーデックが再パースする（ネストされたデシリアライズ / 生パケット生成）あるいはビジュアライザが
リンク先プロトコルとしてネストするワイヤバイトを特定しない。そのリージョンは次のように
特定される：

- `next` が `bytes` フィールドに宣言されている場合、そのフィールドのバイトが**ペイロード
  そのもの**である（上記の VXLAN `innerFrame` の例のとおり）。
- `next` が `bytes` 以外の判別子フィールド（例：IPv4 の `protocol`、`int`）に宣言されている
  場合、ペイロードは `category: payload-marker`（§5.1）でマークされたフィールドから始まる
  リージョンである。`payload-marker` フィールドが存在しない場合は、最後の body フィールド以降の
  囲むスコープに残るすべてのバイトである。

**判別式（GENEVE / 条件付きリンキング）：**

リンク先プロトコルが単一フィールド値ではなく複数フィールドの組み合わせで決まる場合、
`next` を持つフィールドは `_` キャッチオールキーと `when` 条件を組み合わせることができる
（未仕様；ツールレイヤ拡張）。現在の PSDL では、`next` マップのキーは `next` を宣言した
フィールドの離散値である。ターゲットプロトコルが別のフィールド（例：GENEVE の `protocolType`
が内側フレームの型を決定するが `next` マップはペイロード bytes フィールドにある）で決まる
場合、作者はペイロード bytes フィールドに `next: { _: <default> }` を記述し、依存関係を
`doc` で文書化できる。完全な条件付きリンキングは計画中の拡張。

**クロスレイヤフィールドアクセス（`enclosingField`）：**

内側 PSDL ドキュメントは、`enclosingField` 式形式を使用して直接囲む
プロトコルレイヤの解析済み状態から名前付きフィールドを参照できる：

```yaml
{ kind: enclosingField, field: protocolType }
```

`enclosingField` は `constraints` でのみ有効。body 式での使用は検証エラー
（レイヤをまたいだ前方参照セマンティクスは保証できない）。`constraints` 式以外での
`enclosingField` の使用は検証エラー。参照するフィールド名は囲むレイヤの PSDL ドキュメントの
フィールド id と一致しなければならない。評価時に囲むレイヤが存在しない場合は `0`（不在
フィールド参照と同じ）。囲むレイヤの解析済み状態はコーデックが供給する別個の env であり、
制約評価フェーズ（§10.0）中に利用可能になる。

---

## 8. チェックサムバインディング

```yaml
- id: checksum
  name: Header Checksum
  type: { kind: int, bits: 16 }
  category: checksum
  checksumAlgorithm: internet
  checksumCovers: [version, ihl, totalLength, protocol, src, dst]
```

`checksumAlgorithm` を持つフィールドは、対象フィールドがエンコードされた後にシリアライズ時に
コーデックが計算・充填する（出力では作者が記述したワイヤ値は無視される）。これは長さフィールドに
対する `computedFrom` の契約（§4）に対応する。

### アルゴリズム

| 値 | 説明 |
|----|------|
| `internet` | RFC 1071 ワンズコンプリメント和（IP、ICMP、IGMP） |
| `crc32` | CRC-32 / ISO 3309（Ethernet FCS） |
| `crc32c` | CRC-32C / Castagnoli（iSCSI、NVMe） |
| `crc16` | CRC-16 / IBM |
| `adler32` | Adler-32 |

このリストにないアルゴリズムには任意の文字列が使える。コーデックが実装する責務を持つ。

### アルゴリズムパラメータ（`checksumParams`）

多項式や処理フラグのみが異なる CRC バリアントの完全なパラメータ化：

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

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `polynomial` | integer | 生成多項式（通常・非反射形式） |
| `initValue` | integer | 初期レジスタ値 |
| `finalXOR` | integer | 最終 CRC と XOR する値 |
| `inputReflect` | boolean | 処理前に各入力バイトを反射するか |
| `outputReflect` | boolean | XOR 前に最終 CRC を反射するか |

全 `checksumParams` フィールドはオプション。名前付きアルゴリズムは既知の暗黙パラメータを持ち、
指定された場合は `checksumParams` がそれを上書きする。既知の名前付き CRC アルゴリズム
（`crc32`・`crc32c`・`crc16`）に対して `checksumParams` を使用する場合、ツールは
**lint 警告**を発すること（SHOULD）。そのオーバーライドにより名称のとおりの標準アルゴリズムと
異なる結果になる可能性があるため、偏差を明示するためにカスタムアルゴリズム名
（例：`crc32-custom`）を使用することを検討すること。

CRC パラメータモデルを使用しない名前付きアルゴリズム（`internet`・`adler32`）に対して
`checksumParams` を使用することは検証エラー。これらのアルゴリズムは CRC パラメータセットと
構造的に互換性のない固定内部パラメータを持つ。

### `checksumCovers` 省略形

`checksumCovers` は個別フィールド id・**ref コンテナ id**・**repeat コンテナ id** を受け入れる。
展開ルールは以下のとおり：

- ドット付きリーフ id（例：`src.oct0`）— その単一フィールドのみを対象とする。
- ref コンテナ id（例：`src`）— 定義順でその def のすべてのリーフフィールドに展開される。
- repeat コンテナの `id`（例：`chunks`）— パース順ですべてのイテレーションの連結ワイヤバイトに
  展開される。これにより可変数の繰り返し要素にまたがるチェックサム（例：SCTP CRC32c を
  全チャンクに対して計算）を各要素を静的に列挙することなく表現できる。`checksumCovers` に
  repeat コンテナ id が現れる場合、個々の `align` コンテナに `id` があるかどうかに関わらず、
  各イテレーションが消費したすべてのバイトが展開に含まれる。`align` のデフォルト除外ルール
  （§5）が適用されるのは、`checksumCovers` リストに囲む repeat コンテナを含まない
  トップレベルまたは struct レベルのチェックサムフィールドに対してのみ。

```yaml
checksumCovers: [version, ihl, totalLength, protocol, src, dst]
# 'src'・'dst' → src.oct0…src.oct3、dst.oct0…dst.oct3 に展開

checksumCovers: [commonHeader, chunks]
# 'chunks' は repeat → その repeat の全イテレーションの全バイト範囲に展開
```

ドット形式（`src.oct0`）とコンテナ省略形（`src`・`chunks`）は同じリスト内で混在させることができる。
展開はチェックサム計算前にコーデックが行う。

チェックサムフィールドが `repeat` 要素の内部に現れる場合、その `checksumCovers` 内の id は
現在のイテレーションのスコープ（repeat インデックス付きの `#N` インスタンス）内で、`ref`
（§10.4）とまったく同様に解決される。これにより per-block のインターリーブされた CRC — 例：
16 バイトブロックごとに 2 バイトの CRC を持つ DNP3 データリンクフレーム（IEEE 1815）を
`{ data, crc }` の `repeat` としてモデル化したもの — が表現可能になる：`crc` フィールドの
`checksumCovers` はそのイテレーションローカルの兄弟 `data` を列挙し、それはそのイテレーションの
`data#N` に解決される。

### 擬似ヘッダ（`checksumPseudoHeader`）

```yaml
- id: checksum
  checksumAlgorithm: internet
  checksumPseudoHeader: ipv4
  checksumCovers: [srcPort, dstPort, dataOffset, flags, windowSize,
                   urgentPointer, data]
```

| 値 | 擬似ヘッダの内容 |
|----|----------------|
| `ipv4` | src addr、dst addr、ゼロ、プロトコル、セグメント長（RFC 793 §3.1） |
| `ipv6` | src addr、dst addr、上位レイヤパケット長、ゼロ、next header（RFC 2460 §8.1） |

---

## 9. 制約

制約は body パースとは独立して評価される等式関係を表現する。

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

**制約評価ルール：**

- 参照するフィールドのいずれかが不在の場合、制約は**サイレントスキップ**。
- `lhs` または `rhs` が再帰的 def 展開内のフィールドを参照する制約は、
  評価およびバックプロパゲーション中に**常にサイレントスキップ**される
  （§6「再帰的 def — 制限」参照）。そのような制約を検出した場合、ツールはロード時に
  lint 警告を出すこと（SHOULD）。
- 全フィールドのパース後に等値チェック。不一致は**検証警告**（ハードエラーではない）。
- コーデックバックプロパゲーション：単一未知数の線形式のみ自動解決可能。
  多未知数または非線形制約は検証にのみ使用。
- バックプロパゲーションは**フィックスポイント反復**しなければならない：
  1 パスで新たなフィールドが解決されなくなるまで繰り返す。

---

## 10. 式評価ルール

### 10.0 処理モデル：`env` とフェーズ

**env** は式を評価する対象となる、解決済みフィールド値のキー・バリューマップである。
キーはフィールド id（ref 展開されたドット付き id や repeat インデックス付き id を含む）、
値は整数。処理は次の 4 つの順序付きフェーズで進む：

1. **Seed（シード）** — `const`/`defaultValue` 値（§10.2）およびデコーダが注入する値
   （例：`count: eos` repeat のイテレーション数 `env[repeat.id]`（§10.7）、および
   トップレベル `body` で `enclosingBits` を裏付ける**トップレベルパケットのビット数**）で
   env を初期化する。シーディングはすべて、パースや正規化の前に行われる。なお、
   `encrypted.plaintext` の `enclosingBits` はシード注入**されない**：それは囲む `encrypted`
   コンテナの `wireBits` 式に等しく、その式は暗号化コンテナが Parse フェーズ中に入られたときに
   評価される（§10.1 参照）。
2. **Parse（パース）** — body をドキュメント順に走査し、ワイヤバイトを読み取り、現在の
   env に対して body 式を評価し、各フィールドを読み取るたびにその値を env に書き込む。
   `peek`（§10.6）はこのフェーズで消費せずに先読みする。
3. **Normalize（正規化）** — シーディング時に注入されたがパースで生成されなかったカウント
   に依存する位置を解決する（例：`env` キーが不在の `eos` repeat はデフォルトで `0`
   イテレーションとなる）。
4. **Constraint evaluate / back-propagate（制約評価/バックプロパゲーション）** —
   完全にパースされた env に対して `constraints` を評価し、フィックスポイントソルバー
   （§9）を実行する。

以下の `eos`/`peek`/`constraint` のルールはこれらのフェーズを名前で参照する。
「正規化前」とはシードフェーズ中を意味する。

`enclosingField` 式（§4、§7）は、このドキュメントの env ではなく、コーデックが供給する
**別個の囲むレイヤの env** から読み取る。これは constraints 専用の形式であり、したがって
制約評価フェーズで解決される。囲むレイヤが存在しない場合は `0` を返す。

### 10.1 スコープ（body 式）

body コンテナ内の式は、ドキュメント順（上から下、深さ優先走査）で**現在のコンテナよりも前**
に現れるフィールドのみ参照できる。適用対象：`bytes.n`・`repeat.count`・`switch.on`・
`optional.when`・`encrypted.wireBits`・`bounded.bytes`・`virtual.expr`・`wireSize.target`
（body 式ではターゲットがドキュメント順で `wireSize` 式よりも前に現れなければならない）。

`peek` 式はストリームを先読みするため、未解析データを読み取ることができる唯一の式形式（§4）。
`enclosingBits` は**トップレベル `body` でのみ**前方参照制限の例外である。そこでは
ストリームからの読み取りではなく、パース開始前から利用できるデコーダ注入の定数だからである。
`encrypted.plaintext` struct 内では、`enclosingBits` は囲む `encrypted` コンテナの `wireBits`
式の結果に等しく、その式は暗号化コンテナがパース中に入られたときに評価される。したがって
そこでの `enclosingBits` は**通常の前方参照ルールの対象**である — その `wireBits` 式が参照する
すべてのフィールドはドキュメント順で `encrypted` コンテナより前になければならない。
`constraints` 式はこのルールを完全に免除される。

### 10.2 デフォルト値のシーディング

評価開始前に以下の優先順位（高い順）で env に値を注入する：

1. **`const` 値（最高優先度）。** `const` と `defaultValue` が両方ある場合は `const` が勝つ。
2. `const` でまだ設定されていない場合、`defaultValue` の値。
3. `defs`・`group`・`optional`・`encrypted` 内でも再帰的に適用される。
   これにはワイヤ上で最終的に不在になる可能性があるフィールドも含む。
   `recursive: true` def では、シーディングは def ボディに直接宣言されたフィールドにのみ
   適用され、同じ def への再帰的に展開された `ref` インスタンスには適用されない。
   def 内の再帰的 `ref` コンテナはシーディングにおいて未解決の境界として扱われる
   （§6 の制約ソルバーのルールと同じ）。
   **body 式**（制約ではない）が再帰的展開インスタンス内のフィールドを参照する場合、
   値は不在フィールド参照と同様に解決される：その def ボディ宣言からのシード値、
   またはシードが定義されていない場合は `0`（§10.3 と同じ、§6 の制約ソルバーが
   そのような参照を解決不能な未知値として扱うのとは異なる）。

### 10.3 不在フィールドの参照

不在フィールドを参照する式は §10.2 のシード値か `0` を返す。エラーではない。
これは意図的な設計で、optional フィールドを分岐なしに扱える。このルールは
再帰的展開 def インスタンス内のフィールドにも適用される：そのようなフィールドへの
body 式参照は def ボディ宣言からのシード値か `0` を返す（§10.2 ルール 3 参照）。
制約式は異なるルールに従う：再帰境界フィールドは制約ソルバーによって解決不能な
未知値として扱われる（§6）。

### 10.4 repeat 要素スコープ

同じイテレーション内の前フィールドのみ参照可能。前のイテレーションは `ref` では参照不可。
`until` は各完全イテレーションの後に評価され、現在の（直前にパースされた）イテレーションの
任意のフィールドを参照できる。
バイト境界の反復には、repeat を `count: eos` の `bounded` スコープでラップする
（標準的な記述は §5 bounded スコープ）。
`prevIter` 式（§4）は `until` 式で使用可能で、ループ終端条件のために最後に完了した
イテレーションのフィールド値を参照する。イテレーション間の不変条件（単調増加シーケンス番号
など）は PSDL では表現しない。§9 の制約またはコーデックレイヤに委ねる（§4 `prevIter` の注記）。

### 10.5 switch の非選択アーム

非選択アームのフィールドは env に追加されない。後続式での参照は §10.2 のシード値か `0`。
constraints からの参照はサイレントスキップ。

### 10.6 peek のパース位置

| コンテキスト | 現在のパース位置 |
|-------------|----------------|
| `switch.on` | switch コンテナの最初のビット |
| `optional.when` | optional コンテナの最初のビット |
| `repeat.count`（固定形式） | 最初の要素の最初のビット |
| `repeat.count.until` | 直前に完了したイテレーションの最後のバイトの直後の最初のビット |

4 つのコンテキストすべてにおいて、位置は**現在の（最も内側の）スコープのサブストリーム**の
カーソルである。`offset`（§4、ビット単位）はそこからビット単位で前方へ進む。最も内側の
スコープ提供コンテナの残りバジェットを超えて読もうとする `peek` は、利用可能データを超えて
読むものとして扱われ、`0` を返す（§4）。たとえ基底バッファ内にスコープ境界を超えるバイトが
存在していても同様である。

### 10.7 `eos` repeat のイテレーション回数

`count: eos` repeat について、デコーダは**シード**フェーズ（§10.0）中に、repeat の `id`
に等しいキーを使ってイテレーション数を env に注入しなければならない（MUST）：

```
env[repeat.id] = <完了イテレーション数>
```

このキーが存在しない場合（例：静的レイアウトプレビュー時）、**正規化**フェーズが
デフォルトで `0` イテレーションとする。ストリームデコードするツールは end-of-stream を
検出するまでループしてからカウントを注入する。

デコーダ/コーデックは**固定カウント** repeat についても `env[repeat.id]` を設定しなければ
ならない（MUST）（それは評価された `count` 式に自明に等しい）。これにより repeat コンテナの
`id` への `ref`（§4）が `eos` と固定カウントの両方の repeat について完了イテレーション数を
一様に返し、カウントフィールドが制約 `countField == <repeatId>` を通じてバックプロパゲーション
できる。

### 10.8 ネストされた optional の評価

内側の `when` は外側の optional が存在する場合にのみ評価される（ショートサーキット評価）。
外側が不在の場合、内側は `when` を評価せずに不在として扱われる。任意のネスト深さに適用される。

---

## 11. エラー挙動

### 11.1 検証エラー（ロード/パース時に検出）

| 条件 | エラー |
|------|--------|
| 必須フィールドの欠如（`name`、`body` 等） | 検証エラー |
| フィールド id が `[a-zA-Z][a-zA-Z0-9_-]*` に不一致 | 検証エラー |
| フィールド id に `.` を含む | 検証エラー |
| `ref` ターゲットが `defs` またはインポートに存在しない | 検証エラー |
| `recursive: true` でないパスを通じた循環参照 | 検証エラー |
| `peek` を `switch.on` / `optional.when` / `repeat.count`（`.until` を含む）以外で使用 — 例：`bytes.n`・`encrypted.wireBits`・`constraints` | 検証エラー |
| `enclosingBits` を、注入されたビットバジェットを持つスコープ提供コンテナ（すなわち `encrypted.plaintext` struct またはトップレベル `body`）の外で使用 | 検証エラー |
| `remaining`/`enclosingBits` を、`encrypted` コンテナが `wireBits` を省略している `encrypted.plaintext` の内部で使用 | 検証エラー |
| `switch` ケースキーの形式が無効 | 検証エラー |
| `berLength.maxBytes` > 5 | 検証エラー |
| `remaining` をスコープ提供コンテナ（`bounded` スコープ・`encrypted.plaintext` struct・トップレベル `body`）の外で使用 | 検証エラー |
| CRC 以外の名前付きアルゴリズム（`internet`・`adler32`）への `checksumParams` 使用 | 検証エラー |
| フィールド id が複数の `rendererHints.sections` エントリに現れる | 検証エラー |
| `rendererHints.sections` エントリの `fields` リストが空 | 検証エラー |
| `rendererHints.sections.fields` エントリがトップレベル body コンテナまたはフィールド id に対応しない | 検証エラー |
| `align` コンテナの `to` 値が 8 の倍数である正の 2 のべき乗でない | 検証エラー |
| `lookup` テーブルキーが非負の 10 進数整数でない | 検証エラー |
| `lookup` テーブル値が非負の 10 進数整数でない | 検証エラー |
| 同じ `as` プレフィックスの 2 つのインポート | 検証エラー |
| インポートの循環チェーン | 検証エラー |
| インポートの `source` が解決不能 | 検証エラー |
| `ref` ターゲットが推移的インポートのみを通じて解決される（このドキュメントの `imports` に直接列挙されていない） | 検証エラー |
| `defs` キーまたはインポートエントリが `imports` ですでに導入された名前を再宣言する | 検証エラー |
| インポート修飾 def 名（例：`addr.ipv4Addr`）を `checksumCovers` に直接使用 | 検証エラー |
| `wireSize` を body 式で使用し、`target` がドキュメント順で `wireSize` 式より後に現れる | 検証エラー |
| `wireSize` を body 式で使用し、`target` が囲む/まだ閉じていない（パーススタック上でまだ開いている）コンテナである | 検証エラー |
| ドキュメント順でその repeat より前にある body 式で repeat コンテナの `id` への `ref` を使用 | 検証エラー |
| `virtual` フィールドが `defs` struct ボディ内に配置されている | 検証エラー |
| `prevIter` を `repeat.count.until` 外で使用 | 検証エラー |
| `wireSize` 以外の式で `computedFrom` を使用 | 検証エラー |
| `enclosingField` を `constraints` 式外で使用 | 検証エラー |

### 11.2 ランタイムエラー（既知の値での正規化/デコード時）

| 条件 | エラー |
|------|--------|
| 式のゼロ除算または剰余 | ランタイムエラー |
| `const` 値の不一致 | ランタイムエラー |
| `berLength` ワイヤエンコード長が `maxBytes` を超える | ランタイムエラー |
| コーデックが実装していないエンコーディング文字列の `varint` フィールドに遭遇した | ランタイムエラー |
| デコーダが総パケットサイズを注入していない状態でトップレベル `body` 式中の `remaining` または `enclosingBits` を使用 | ランタイムエラー |
| 計算されたパディングが囲む `bounded` スコープの残りバイトバジェットを超える `align` | ランタイムエラー |
| カーソルがバイトの途中（バイトアライメントされていない）状態で `remaining` を使って `bytes` フィールドをサイズ指定 | ランタイムエラー |

### 11.3 サイレント / フォールバック挙動

| 条件 | 挙動 |
|------|------|
| 不在フィールドへの参照 | §10.2 のシード値か `0` |
| 一致なし・`_` なし `switch` | ゼロバイト消費（空 struct） |
| `variants` にない `enum` 値 | 生整数として受け入れ（ラベルなし） |
| `varint` オーバーフロー | デコーダ定義 |
| 不在フィールドを参照する constraint | サイレントスキップ |
| constraint 値の不一致 | 検証警告 |
| `peek` が利用可能データを超える | `0` |
| env 注入のない `eos` repeat | ゼロイテレーション |
| テーブルにないキーでの `lookup` | `0` |
| `lookup` キー式が負の整数に切り捨てられる | `0`（キー未発見と同じ；すべてのキーは非負） |
| 再帰的 def 展開内のフィールドを参照する constraint | 評価とバックプロパゲーションの両方でサイレントスキップ |

### 11.4 lint 警告（ロード時の勧告、ハードエラーではない）

| 条件 | 勧告 |
|------|------|
| ドキュメントに `version` がない | バージョン未宣言の警告 |
| constraint の `lhs` または `rhs` が再帰的 def 展開内のフィールドを参照する | lint 警告：制約は常にサイレントスキップされる |
| `checksumParams` が既知の名前付き CRC アルゴリズム（`crc32`・`crc32c`・`crc16`）とともに使用されている | 勧告：オーバーライドにより実効アルゴリズムが変わる。明示するためにカスタムアルゴリズム名の使用を検討すること |

---

## 12. バイトオーダー

| 型 | パケットレベル適用？ | フィールドレベルオーバーライド？ |
|-----|---------------------|-------------------------------|
| `int` | はい | はい |
| `enum` | はい | はい |
| `bits`（バイト境界、n が 8 の倍数かつ 8 超） | はい（パケットレベルのみ） | いいえ |
| `bits`（それ以外の幅、またはバイト境界でない） | いいえ（生の MSB-first ビット列） | いいえ |
| `bytes` | いいえ（バイトオーダー非依存） | いいえ |
| `varint` | いいえ（エンコーディング依存） | いいえ |
| `berLength` | いいえ（エンコーディング依存） | いいえ |

パケットレベルの `byteOrder` は、`bits` フィールドが**バイト幅が整数（n が 8 の倍数かつ
8 超）かつバイト境界から始まる**場合にのみ適用される。そのようなフィールドは同じ幅の `int` とまったく
同様にバイトオーダースワップの対象となるマルチバイト値として読まれるが、フィールドレベルの
オーバーライドはない。そのようなフィールドにフィールドレベルのバイトオーダー制御が必要な
場合は `int` とマスクを使用すること。

幅が 8 の倍数で**ない**、またはバイトの途中で始まる/終わる `bits` フィールドは、
**バイトオーダースワップのない生の MSB-first ビット列**として扱われる。バイトオーダー
スワップは完全なバイトに対してのみ定義されるため、バイト境界上で完全なバイトを占めない
フィールド（例：12 ビットの `bits` フィールド）には適用できない：「どのバイトをスワップ
するか」という整合的な概念がない。そのようなフィールドの読み取りは、現在のカーソル位置から
最上位ビットを先頭にビット単位で進む。カーソルをバイトの途中に残す直前のサブバイト
フィールドは、バイトオーダーとはまったく相互作用しない。そのようなフィールドの後に `align`
（§5）が続く場合、align の切り上げはこの生ビット列に適用される：カーソルはバイトの途中の
位置から次の完全なバイトへ、その後 `to` 境界へ切り上げられ、バイトオーダースワップは伴わない。

```yaml
byteOrder: BE
body:
  - id: seq
    name: Sequence Number
    type: { kind: int, bits: 32 }      # BE を継承；フィールドレベルオーバーライド可
  - id: leField
    name: LE Field
    type: { kind: int, bits: 16 }
    byteOrder: LE                       # オーバーライド
  - id: flags
    name: Flags
    type: { kind: bits, n: 16 }        # パケットレベル BE に従う；フィールドレベルオーバーライド不可
```

---

## 13. レンダラーヒント

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
```

| プロパティ | デフォルト | 説明 |
|-----------|-----------|------|
| `rowBits` | `32` | ワイヤ図の 1 行あたりのビット数 |
| `sections` | `[]` | ビジュアルセクションラベル（表示専用） |

`rowBits` をトップレベルに配置する方式（pre-0.5）は後方互換性のために受け入れる。

### `sections`

各セクションエントリは名前付きビジュアルリージョンを宣言する：
`id`（必須）・`label`（必須）・`fields`（必須）。

セクションはワイヤレイアウトや式スコープに影響しない。
どのセクションにも列挙されていないフィールドはセクションヘッダなしで表示される。

`sections.fields` で有効なエントリの種類：

| エントリ種別 | 展開 |
|------------|------|
| Field `id` | その単一フィールドをセクションに割り当てる |
| Group `id` | グループとその全子をセクションに割り当てる |
| Repeat `id` | repeat コンテナ（全イテレーション）をセクションに割り当てる |
| Switch `id` | switch コンテナ（全アーム）をセクションに割り当てる |
| Optional `id` | optional コンテナ（存在・不在を問わず）をセクションに割り当てる |
| Bounded `id` | bounded スコープコンテナをセクションに割り当てる |
| Encrypted `id` | encrypted コンテナをセクションに割り当てる |

その他の値（body コンテナまたはフィールド id に対応しない id を含む）は検証エラー（§11.1 参照）。

**セクションのルール：**

- セクションの `fields` リストは空であってはならない。フィールド id がゼロのセクションは
  検証エラー。
- フィールド id は複数のセクションに現れてはならない。重複リストは検証エラー。
- `rendererHints.sections` のセクション順序は body フィールド順序から独立しており、
  希望する表示順のみを表す。レンダラーはリストの順にセクションを表示し（SHOULD）、
  各セクション内のフィールドは `fields` リストで示された順に表示すること（SHOULD）。
  `body` 内での位置は関係ない。

---

## 14. コード生成ヒント

### `abbrev` — プロトコルフィルタ名

```yaml
name: tcp
abbrev: tcp   # Wireshark フィルタ：tcp.srcport、tcp.flags 等
```

省略時は `abbrev` が `name` にデフォルトする。codegen ツールは各フィールドの Wireshark
フィルタ abbrev として `{abbrev}.{field.id}` を使う。合成された id については、codegen は
ref 展開フィールドに対して**`.` で連結した作成者記述の id パス**（`{abbrev}.src.oct0`）を
使い、繰り返しフィールドのすべてのイテレーションが 1 つのフィルタ abbrev を共有するように
**`#N` の repeat インデックスサフィックスを取り除く**（`{abbrev}.options.type`）。`#N` は
フィールドのプロトコル名の一部ではなくランタイムのインスタンスハンドル（§6）だからである。

### `display` — 表示ヒント

```yaml
- id: etherType
  name: EtherType
  type: { kind: int, bits: 16 }
  display: hex   # 2048 ではなく 0x0800 で表示
```

数値フィールド（`int`・`enum`・`bits`）では `display` は表示基数を選択する：

| 値 | 説明 |
|----|------|
| `dec` | 10 進数（デフォルト） |
| `hex` | 16 進数 |
| `oct` | 8 進数 |
| `bin` | 2 進数 |

`bytes` フィールドでは `display` はペイロードの描画方法を選択し、codegen がフィールド型
（Wireshark の `FT_STRING`/`FT_BYTES`/`FT_ETHER`、scapy の `StrField`/`Field`/`MACField`）を
選んだり、ビジュアライザが hex ダンプの代わりにテキストやアドレスグループを描画したりできる：

| 値 | 説明 |
|----|------|
| `hex` | 生のバイトブロブ、hex ダンプ（`bytes` のデフォルト） |
| `ascii` | ASCII テキスト（例：HTTP リクエストライン、SIP） |
| `utf8` | UTF-8 テキスト |
| `addr` | 構造化アドレス（MAC、IPv6、…） |

`display` は**表示専用**でワイヤセマンティクスを持たない。`bytes` ではパースやラウンドトリップに
影響しない。

---

## 15. バージョン互換性

`version` フィールドはこのドキュメントがターゲットとする PSDL 仕様バージョンを宣言する。
形式は `"MAJOR.MINOR"`（例：`"0.5"`）。オプションだが強く推奨される。

**ルール：**

- `version` が存在し、ツールのサポート範囲外の場合、ツールは検証警告を出さなければならない（MUST）。
- `version` が存在しない場合、ツールはパースを試みつつバージョン未宣言の警告を出すこと（SHOULD）。
- ドキュメントの `MAJOR` がツールのサポートより高い場合はハードエラーとして扱うこと（SHOULD）。
- 同じ `MAJOR` でドキュメントの `MINOR` が高い場合は寛容にパース（未知プロパティを無視）し警告（SHOULD）。
- 後方互換性：0.5 ツールはすべての有効な 0.4 ドキュメントを正しくパースしなければならない（MUST）。

```yaml
version: "0.5"
```

---

## 16. 設計境界：forward-only モデルと end-relative 参照

PSDL のコアパースモデルは **forward-only・相対・単一パケット**である。body 式は
ドキュメント順で前に現れるフィールドのみ参照でき（§10.1）、位置は現在のパースカーソルまたは
囲みスコープを基準とした相対値で、1 ドキュメントは自己完結した 1 パケット型を記述する。
これは意図的な制約であり、パースを単一パス・ストリーミング可能に保ち、visualizer の漸進描画を
可能にし、コーデックジェネレータが実装すべき複雑性を抑える。本仕様の各所に散在する out-of-scope
note（§3 DNS 名前圧縮、§3 テンプレート定義レイアウト、§5 TLS 1.3 inner content type、
§5 RTP/SRTP パディング）が個別パターンを範囲外と宣言しているが、本節はそれらすべての背後にある
**問題意識**を一箇所に集約し、将来の改訂で再検討できるよう境界を記録する。

### 16.1 end-relative / 後方参照ファミリ

実在プロトコルには、領域の**末尾**に置かれた値が**前方**のフィールドのサイズや意味を決める
（＝前方フィールドの正しいパースにストリーム後方の値が必要）という認識可能なファミリが存在する。
PSDL はこのファミリのデータ依存メンバーを表現できない。後方読み、または「末尾までスキャンして
巻き戻る」二段階パースを要するためである。

| パターン | 例 | 現状表現可能? |
|---------|-----|--------------|
| 末尾から**定数オフセット**の固定長トレーラ | IPsec ESP `Next Header`+`Pad Length`（末尾2バイト）をブロブ扱い | ✅ end-anchored field（`remaining − <定数>`、§5） |
| **値が前方フィールドをサイズする**末尾オクテット | RTP/SRTP パディングカウント（末尾オクテットがペイロード長を決定） | ❌ back-off距離がデータ依存 |
| 末尾からの**後方スキャン** | TLS 1.3 inner content type（最後の非ゼロバイト） | ❌ 逆方向スキャンが必要 |
| 末尾ポインタからの**ランダムアクセス遡及** | ZIP End-of-Central-Directory→central directory→local header；DNS 名前圧縮ポインタ | ❌ 絶対後方ジャンプが必要、フォーマット全体が末尾起点 |

境界は明確：**末尾からの定数オフセットは表現可能**（`remaining − <定数>` のデータフィールドの後に
通常フィールドを並べる）。**値依存の back-off・後方スキャン・ランダムアクセスジャンプは不可能。**

### 16.2 クロスコンテキスト状態ファミリ

第二のファミリは、後続領域のレイアウトを選ぶために**現在のパケット外**（または先行パース済みの
セッション状態）の情報を必要とする：

- **MP-BGP / BGP-4 `AS_PATH`** — AS 番号が 2 バイトか 4 バイトかは、先行する OPEN メッセージの
  4-octet-AS capability（RFC 6793）でネゴシエートされ、UPDATE には載らない。
- **IPFIX / NetFlow v9 データレコード** — フィールドレイアウトは Template Record 由来
  （テンプレートが同一パケットに載っていてもデータレコード自体は自己記述的でない）。
- **デルタ符号アキュムレータ** — 例：CoAP オプションの絶対番号は先行する全オプションデルタの
  累積和。fold/accumulator プリミティブが無い（§4 `prevIter` は直近イテレーションのみ露出）。

これらは同根の理由で範囲外：1 PSDL ドキュメントは自己記述的な 1 パケット型を記述し、
セッション状態の入力チャネルを持たない。

### 16.3 否定ではなく先送り

どちらのファミリのサポートも構造的に異なるエンジンを強いる。後方/ランダムアクセスアドレッシング
（単一パスストリーミングを破壊）か、セッション状態入力チャネル（単一パケットモデルを破壊）である。
両者とも実在の非自明な機能で、複数の主要プロトコル（RTP、ZIP、MP-BGP、IPFIX）が現に必要とする。
ここに**認識された限界**として記録する（プロトコルが重要でないという意味ではない）。将来の改訂は、
現モデルへの適合度が高い順に以下を導入し得る：

1. **境界付き後方ウィンドウ** — 固定長の末尾領域に限定した end-relative アドレッシング
   （RTP/SRTP パディングと ESP のデータ/パディング分離をカバー）。任意ランダムアクセスは許さない。
2. **セッションコンテキスト入力** — コーデック供給の宣言済み状態マップ（例：ネゴシエート済み
   capability）を `enclosingField` のように参照可能にする（MP-BGP ASN 幅・IPFIX テンプレートをカバー）。
3. **fold/accumulator 式** — repeat イテレーションにわたる畳み込み（CoAP 絶対オプション番号等をカバー）。

それまでは、これらは codec/tool 層の関心事である。生バイトは常に表現可能（RTP ペイロード+パディングを
1 つの `bytes` ブロブ、IPFIX データセットを不透明バイトとして）であり、その**解釈**のみが範囲外。
