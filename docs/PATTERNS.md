# Optimized scalar patterns

All recipes enumerate the unsigned seeds `start <= seed < start + count` and
skip scalar zero. Scalars are reduced modulo the selected curve's group order
`n`. The byte width `w` is 32 for P-256, 48 for P-384 and **66** for P-521.
P-521's extra seven encoding bits are not masked before reduction.

| CLI pattern | Mapping identifier | Scalar construction | Seed domain |
| --- | --- | --- | --- |
| `repeat-byte` | `repeat-byte-mod-order-v1` | Repeat the one-byte seed `w` times; interpret big endian, modulo `n` | 0–255 |
| `repeat-u16be` | `repeat-u16be-mod-order-v1` | Repeat the two-byte big-endian seed `w/2` times, modulo `n` | 0–65,535 |
| `prefix-u32be` | `prefix-u32be-mod-order-v1` | Four big-endian seed bytes followed by `w-4` zero bytes, modulo `n` | unsigned 32-bit |
| `order-minus-counter` | `order-minus-counter-v1` | `(n - seed) mod n` | unsigned 32-bit |
| `single-bit` | `single-bit-v1` | `2^seed mod n` | 0–255 / 383 / 520, depending on curve |
| `repeat-u32be` | `repeat-u32be-mod-order-v1` | Repeat the four-byte big-endian seed `floor(w/4)` times, padding on the left with `w mod 4` zero bytes; reduce modulo `n` | unsigned 32-bit |
| `prefix-u16be` | `prefix-u16be-mod-order-v1` | Two big-endian seed bytes followed by `w-2` zero bytes, modulo `n` | 0–65,535 |
| `low-ones` | `low-ones-mod-order-v1` | `(2^(seed+1) - 1) mod n` | 0–255 / 383 / 520 |
| `all-ones-minus-counter` | `all-ones-minus-counter-mod-order-v1` | `(2^(8*w) - 1 - seed) mod n` | unsigned 32-bit |
| `clear-bit` | `clear-bit-mod-order-v1` | `(2^bits - 1 - 2^seed) mod n`, where `bits` is 256, 384 or 521 | 0–255 / 383 / 520 |

Patterns use the existing `WKPACK01` envelope and lookup record format. The
recipe omits the `hash` and `encoding` fields, whose values are mandatory for legacy
hash-counter recipes. A pattern recipe specifying either value is rejected;
absent and null values are treated identically.
Old hash-counter packs retain their original byte representation and hashes.
The first five families were introduced in version 0.2; the next five in 0.3.
Older readers reject mappings they do not implement.

Linear or affine families advance by one fixed public point per seed.
Single-bit candidates double; low-ones candidates double and add `G`;
clear-bit candidates double and subtract the all-ones bit-mask point.
The generator derives each chunk's initial scalar independently. Chunks of at most 2,048 points
are normalized together and generated in parallel. Nonzero starting seeds,
chunk boundaries and the unsigned-32-bit endpoint are tested. Full public-key
re-derivation verifies each lookup match independently of the batch generator.

`generate-pattern` defaults to the remaining seed domain capped at 100,000;
explicit `--count` values outside the domain are rejected. The first four
patterns omit seed zero because it produces the invalid scalar zero.
`repeat-u32be` and `prefix-u16be` also omit zero. `single-bit` and `low-ones`
include seed zero, which produces scalar one. `all-ones-minus-counter` and
`clear-bit` include zero because its candidate is nonzero. The generator detects
identity points directly rather than assuming a seed always produces a key.

The historical version 0.2 pattern bundle covered all three curves and the first five families.
For each curve it includes 255 repeated-byte records, 65,535 repeated-word
records, 99,999 prefix records, 99,999 order-minus-counter records, and one
record per supported bit position. Repeated-byte and repeated-word recipes
overlap deliberately. Findings retain every matching recipe. The current
`build-db` defaults cover all ten families, with `--count` defaulting to one
million candidates per class and capped by each domain. Use repeatable
`--class-count scalar:<pattern>=N` overrides to raise individual classes; the
builder validates the complete plan before generating packs.

These are explicitly defined weak-key hypotheses. They do not exhaust sparse
scalars, mixed word patterns, seed encodings, PRNG implementations or low-entropy
key generation generally. Testing a specific historical PRNG defect requires
the exact algorithm and key-generation behavior; no generic PRNG emulator is
implied by these packs.
