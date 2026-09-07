# @packet-schema/core

**PSDL**（Packet Schema Definition Language）の型・仕様・参照実装。

PSDL はネットワークプロトコルのヘッダ構造を宣言的に書くための言語で、ビットレベルの幅・可変長・条件分岐・入れ子スコープを表現する。このパッケージはその **言語そのもの** を提供する — 型定義、正規化、レイアウト解決、制約ソルバ、バリデータ、YAML I/O。

```bash
npm install @packet-schema/core
```

```ts
import { parsePsdl, resolveLayout } from "@packet-schema/core";

const { packet } = parsePsdl(yamlText);
const { cells } = resolveLayout(packet);
// cells: 各フィールドが何行目の何ビット目に来るか
```

---

## 三層構成

同じ言語を 3 つの形で持っている。**食い違ったら仕様書が正典。**

| 層 | 実体 | 役割 |
|---|---|---|
| **規範文書** | `spec/psdl-0.5.md`（§1〜§16） | 正典。`spec/psdl-0.5.ja.md` は参考訳 |
| **機械可読** | `schemas/psdl-0.5.yaml` | JSON Schema。エディタ補完と外部バリデータ用 |
| **実装** | `src/` | この npm パッケージ |

スキーマはサブパスで参照できる:

```ts
import schema from "@packet-schema/core/schemas/psdl-0.5.yaml";
```

YAML の先頭に pragma を書けばエディタが直接読む:

```yaml
# yaml-language-server: $schema=../node_modules/@packet-schema/core/schemas/psdl-0.5.yaml
```

---

## デコーダは入っていない

このパッケージは **構造を扱うだけ** で、実際のバイト列をパースしない。`serialize` / `deserialize` は別パッケージ（`codec`、未作成）の担当。

`normalize` が返すのは「この env のときフィールドは何ビット幅になるか」であって、値そのものではない。可変長フィールド（`varint` / `berLength` / delimiter 終端の `bytes`）は、デコーダが実測値を env に注入する前提で、静的なプレビュー幅を返す（§10.7）。

---

## 公開 API

### パース / 出力

| | |
|---|---|
| `parsePsdl(text)` | YAML → `Packet`。**JSON Schema は実行しない**（後述） |
| `stringifyPsdl(packet)` | `Packet` → YAML |

### 検証

| | |
|---|---|
| `validatePacket(packet)` | §11.1 の検証エラー。未宣言 ref、前方参照、peek 位置、checksum 幅、値辞書規則など |
| `validateContainer` / `isValidExpr` | 部分検証 |

### 正規化とレイアウト

| | |
|---|---|
| `normalize(packet, env, opts)` | env を与えて各フィールドの実効幅を確定する。`viewMode: "wire" \| "semantic"` |
| `resolveLayout(packet, opts)` | 正規化してから行に折り返し、セル座標を返す |
| `initialEnv(packet)` | 宣言された `defaultValue` から初期 env を作る |
| `typeBits` / `selectArm` / `isBytesDelimited` | 幅とアーム選択の下請け |
| `berLenEnvKey` / `varintBitsEnvKey` / `bytesDelimLenEnvKey` | デコーダが実測値を注入する env キー |

`rowBits` を省略した packet は valid で、レンダラは 32 にフォールバックする（§13）。

### 式

`lit` / `ref` / `op` / `cond` / `peek` / `lookup` / `wireSize` / `prevIter` / `remaining` / `enclosingBits` / `enclosingField` でコンストラクトし、`evalExpr` / `evalExprOr` で評価する。`exprRefs` / `walkExpr` / `exprContains` は走査用。

env キーの合成は `peekEnvKey` / `remainingEnvKey` / `enclosingBitsEnvKey` / `wireSizeEnvKey` / `prevIterEnvKey` / `enclosingFieldEnvKey`。手で文字列を組み立てないこと。

### 制約

| | |
|---|---|
| `propagate` / `propagateFixpoint` | 制約から従属値を導出（IHL を動かすとヘッダ長が追従する類） |
| `validateConstraints` | 診断を `ConstraintDiagnostic` として level 付きで返す |

### その他

`collectPsdlRefs`（packet が参照する全 ref id）、`resolveValueEntry` / `matchesPattern`（値辞書 §5.3 の逆引き）、`isField`、語彙定数（`VARINT_ENCODINGS` / `CHECKSUM_ALGORITHMS` / `CATEGORY_TOKENS` / `BIN_OPS`）。

---

## 検証は 4 層ある

どこで何が捕まるかを知っておくと、エラーの出どころが分かる。

| 層 | 何を見るか | どこ |
|---|---|---|
| **JSON Schema** | 形（kind ごとの必須キー、型、閉集合） | `schemas/psdl-0.5.yaml`（このパッケージは実行しない） |
| **`validatePacket`** | 意味（未宣言 ref、順序、peek 位置、checksum 幅…） | `src/validate.ts` |
| **presets の 4 段ゲート** | 上記 + 語彙 + normalize 実行 | `@packet-schema/presets` |
| **利用側** | アプリ固有の不変条件 | 各利用側 |

**注意: `parsePsdl` は JSON Schema を実行しない。** このパッケージは ajv に依存していない（本番依存は `yaml` のみ）。スキーマ検証をしたい利用側は自前で ajv を用意して `schemas/psdl-0.5.yaml` を読む。結果として **presets のゲートのほうが `parsePsdl` より厳しい**。

---

## バージョンの読み方

**パッケージ版と言語版は別軸。**

- `@packet-schema/core` **0.1.1** — この npm パッケージのバージョン
- **PSDL 0.5** — 実装している言語のバージョン。packet の `version: "0.5"` フィールドがこれ

パッケージが 0.2.0 になっても言語が 0.6 になるとは限らないし、その逆も同じ。

---

## 開発

```bash
npm ci
npm run typecheck
npm test        # 372 件
npm run build
```

CI は Node 20 / 22 で同じことをする。

### リリース

```bash
npm version patch      # package.json 更新 + コミット + vX.Y.Z タグ
git push --follow-tags
```

`release.yml` がタグと `package.json` の一致を検証し、`prepublishOnly`（typecheck + test + build）を通してから publish する。認証は npm Trusted Publishing (OIDC) なので `NPM_TOKEN` は無い。provenance 付きなので、どのコミット・どの workflow run が publish したかがレジストリ上で検証できる。

**core → presets の順で publish すること。** presets は core の公開版に依存している。

---

## 関連

- [presets](https://github.com/Packet-Schema/presets) — 184 種の組み込みプリセット
- [visualizer](https://github.com/Packet-Schema/visualizer) — PSDL を図にするビューア

## ライセンス

MIT
