# Optimized scalar patterns (version 0.2)

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

Patterns use the existing `WKPACK01` envelope and lookup record format. The
recipe omits the `hash` and `encoding` fields, which are mandatory for legacy
hash-counter recipes. A pattern recipe containing either field is rejected.
Old hash-counter packs retain their original byte representation and hashes.
Readers before version 0.2 reject the new pattern mappings.

The first four families are linear in their seed: `scalar = seed * C mod n`.
The generator computes the curve point `C*G` once and advances by addition.
Single-bit candidates advance by doubling. Chunks of at most 2,048 points
are normalized together and generated in parallel. Nonzero starting seeds,
chunk boundaries and the unsigned-32-bit endpoint are tested. Full public-key
re-derivation verifies each lookup match independently of the batch generator.

`generate-pattern` defaults to the remaining seed domain capped at 100,000;
explicit `--count` values outside the domain are rejected. The first four
patterns omit seed zero because it produces the invalid scalar zero.
`single-bit` includes seed zero because it produces scalar one.

The standard pattern bundle covers all three curves and all five families.
For each curve it includes 255 repeated-byte records, 65,535 repeated-word
records, 99,999 prefix records, 99,999 order-minus-counter records, and one
record per supported bit position. Repeated-byte and repeated-word recipes
overlap deliberately. Findings retain every matching recipe.

These are explicitly defined weak-key hypotheses. They do not exhaust sparse
scalars, mixed word patterns, seed encodings, PRNG implementations or low-entropy
key generation generally. Testing a specific historical PRNG defect requires
the exact algorithm and key-generation behavior; no generic PRNG emulator is
implied by these packs.
