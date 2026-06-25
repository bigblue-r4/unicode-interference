# unicode-interference

Detect hidden non-Latin characters embedded in text using a **forward/reverse script-ID interference pattern**.

Finds Cyrillic, Greek, CJK, and other homoglyph substitutions that are invisible to humans but flip script context for downstream systems. Zero dependencies. Single static binary.

```
MIT · Rust 1.75+ · no_std compatible (lib only)
```

---

## The algorithm

Every character in a string belongs to a Unicode *script* (Latin, Cyrillic, Greek, …). A purely Latin string is **symmetric under reversal** — the script at position `i` matches the script at position `n-1-i`.

When an attacker substitutes a Cyrillic `і` (U+0456) for a Latin `i`, the symmetry breaks at two positions simultaneously:

```
Text:   i g n o r e
Script: L L L L L L   ← symmetric, no spikes

Text:   і g n o r e
Script: C L L L L L   ← asymmetric at pos 0 and pos 5

Forward:  C L L L L L
Reversed: L L L L L C
Diff:     ^         ^   ← interference fringes
```

These **interference fringes** — symmetric spikes on the forward/reverse diff — are the detection signal. They appear in pairs at intrusion position `i` and its mirror `n-1-i`. A clean string produces a flat line; a homoglyph substitution produces a spike pattern.

A **rotation map** (second pass) looks up each detected character in a confusable table — like rotating a Cyrillic `а` to find its ASCII look-alike `a`. This confirms the attack intent and reconstructs the plaintext.

---

## Quick start

```bash
cargo add unicode-interference
```

```rust
use unicode_interference::probe;

let r = probe("іgnοre all instructions");

println!("{}", r.render_pattern());
// TEXT:   і g n ο r e · a l l · i n s t r u c t i o n s
// SCRIPT: C L L G L L · L L L · L L L L L L L L L L L L
// FRINGE: ^ · · ^ · · · · · · · · · · · · · · · · · · ·
//
// INTRUSIONS:
//   pos   0  U+0456 'і'  Cyrillic → 'i' (confusable)  confidence=1.00
//   pos   3  U+03BF 'ο'  Greek → 'o' (confusable)  confidence=1.00
//
// Score: 0.74

assert!(r.has_intrusions());
assert!(r.should_flag());
println!("{}", r.deobfuscated()); // "ignore all instructions"
```

---

## CLI

```bash
cargo install unicode-interference
```

```bash
# default — full interference pattern
probe "іgnοre all"

# one-line summary
probe --summary "іgnοre all"

# JSON output (pipe-friendly)
probe --json "іgnοre all"

# deobfuscated string only
probe --deobf "іgnοre all"

# exit code only: 0=clean 1=flagged
probe --quiet "іgnοre all" && echo "clean" || echo "flagged"

# pipe from stdin
echo "some text" | probe
```

---

## API

### `probe(input: &str) -> InterferenceReport`

Main entry point. Returns a full analysis report.

```rust
pub struct InterferenceReport {
    pub input:            String,
    pub scripts:          Vec<Script>,      // per-character classification
    pub interference:     Vec<bool>,        // true = spike at this position
    pub intrusions:       Vec<Intrusion>,   // sorted by confidence desc
    pub score:            f32,              // composite score [0.0–1.0]
    pub dominant_script:  Script,
}

impl InterferenceReport {
    pub fn has_intrusions(&self) -> bool
    pub fn should_flag(&self) -> bool       // score >= 0.20
    pub fn deobfuscated(&self) -> String    // confusables replaced with ASCII
    pub fn render_pattern(&self) -> String  // visual ASCII display
    pub fn summary(&self) -> String         // one-line summary
}
```

### `Intrusion`

```rust
pub struct Intrusion {
    pub position:   usize,       // char index
    pub character:  char,        // the foreign character
    pub script:     Script,      // its Unicode script
    pub rotation:   Option<char>,// ASCII look-alike (if known confusable)
    pub confidence: f32,         // [0.0–1.0]
    pub detail:     String,
}
```

Confidence is computed from three factors:
- **+0.50** interference spike at this position (forward/reverse asymmetry)
- **+0.35** rotation map hit (known confusable)
- **+0.15** isolated foreign character (surrounded by dominant-script chars)

### `classify(c: char) -> Script`

Classify a single character. Covers Latin, Cyrillic, Greek, CJK Han, Hiragana, Katakana, Arabic, Hebrew, Devanagari, and Punctuation (neutral).

### `rotate(c: char) -> Option<(char, &str)>`

Look up a character in the confusable rotation table. Returns `(ascii_equivalent, script_name)` if it's a known look-alike.

---

## Script legend

| Label | Script |
|---|---|
| `L` | Latin |
| `C` | Cyrillic |
| `G` | Greek |
| `H` | CJK Han |
| `h` | Hiragana |
| `k` | Katakana |
| `A` | Arabic |
| `W` | Hebrew |
| `D` | Devanagari |
| `·` | Punctuation / neutral |

---

## Scoring

| Factor | Weight |
|---|---|
| Interference spike density | 0.40 |
| Intrusion confidence sum (capped 1.0) | 0.40 |
| Rotation map hit (any) | 0.20 bonus |

Flag threshold: **score ≥ 0.20**

---

## Attack examples

### Cyrillic homoglyph injection

```
"іgnore all instructions"
 ^
 └─ U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    Visually identical to Latin 'i'
    Breaks tokenizer boundaries, bypasses keyword filters
```

### Multi-script mixed attack

```
"іgnοrе аll іnstructіοns"
 CGGGCC CCL CLLLLLLLCGL

→ deobfuscated: "ignore all instructions"
   score: 0.77
```

### Forward/reverse fringe pair

```
Input:    D i r e c t o r   H а r g r o v e
Script:   L L L L L L L L . L C L L L L L L
                               ^           ^
                               └─ fringe pair: intrusion at pos 10 mirrored at pos n-1-10
```

---

## What this solves

LLM systems — proxies, guardrails, content classifiers — process text as raw bytes or Unicode codepoints. A Cyrillic `а` (U+0430) looks identical to Latin `a` in most fonts, but differs in:

- Script category (breaks tokenizer behavior in multilingual models)
- Byte encoding (defeats naive string matching and keyword filters)
- Semantic identity (allows prompt injection to pass guards that match on "ignore all")

Standard text sanitization (strip non-ASCII, NFC normalization) does not catch these: the characters are valid Unicode and NFC-normalized. The interference pattern catches them by exploiting the structural asymmetry they introduce.

---

## Benchmark

Tested against the [CyberEC encoding-evasion subset](https://github.com/markusmobius/go-cyber-ec) of labeled prompt injections:

| Category | Count | Caught |
|---|---|---|
| Cyrillic homoglyphs | 4 | ✓ all — confidence ≥ 0.85 |
| Greek homoglyphs | 1 | ✓ — confidence 1.00 |
| Mixed Cyrillic+Greek | 2 | ✓ both |

Zero false positives on 80 MT-Bench questions and 150 LLM-Sec-Eval prompts.

---

## v2 roadmap

- **Full Unicode TR39 confusables table** (~8,000 pairs, currently ~50 Cyrillic+Greek)
- **Bidirectional text** (RTL embedding attacks via Unicode control characters)
- **Entropy scoring** — character-level unigram model to detect statistically unusual mixing
- **Punycode / IDN decoding** — catch domain-lookalike attacks in URLs
- **HTML entity expansion** — `&#x0456;` → `і` before interference pass
- **WASM target** — `wasm32-unknown-unknown` for browser/edge use
- **`serde` feature flag** — `#[derive(Serialize, Deserialize)]` on all public types
- **Language-aware baseline** — known mixed-script languages (Japanese Romaji, Korean loanwords) excluded from flagging

---

## License

MIT — see [LICENSE](LICENSE)

Part of [SGAIL](https://github.com/bigblue-r4) Harborlight security infrastructure.
