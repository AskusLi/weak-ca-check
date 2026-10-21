# Candidate pack format, version 1

All integers are unsigned big endian. A pack is:

| Field | Bytes |
| --- | ---: |
| ASCII `WKPACK01` | 8 |
| JSON header byte length | 4 |
| UTF-8 JSON header | variable; at most 65,536 |
| Sorted fixed-width records | `records * record_bytes` |
| SHA-256 of all preceding bytes | 32 |

The header identifies format version, exact recipe, record count, record width,
tag width, seed width, and tag algorithm. Unknown fields and unknown mappings
are rejected. Counts and the exact file length are checked before records are
read. The SHA-256 of the *whole file*, including its trailer, identifies the pack
in manifests and findings. Checksums detect corruption; they do not authenticate
the publisher or prove that a third-party pack includes all claimed seeds.
Rebuild from its recipe to verify completeness.

Version 0.2 also supports [explicit scalar patterns](PATTERNS.md). They use the
same envelope with a different mapping and omit hash/encoding recipe fields.
Hash recipes may include an optional `seed_pattern` field. Its value transforms
the stored seed index into the numeric seed value before applying the selected
encoding and hash. An absent field means the original counter mapping, so
existing hash-counter packs keep their original recipe JSON and file hashes.

## Recipe

`digest-be-mod-order-v1` means:

1. Enumerate `start <= seed < start + count`. The stored seed is an index that
   fits unsigned 32 bits.
2. Apply the optional seed-number pattern to that index; without one, use the
   index itself. See [seed patterns](SEED_PATTERNS.md).
3. Encode the resulting unsigned seed number using the named encoding.
4. Compute the named hash, with its standard fixed output length.
5. Interpret the digest as an unsigned big-endian integer and reduce modulo
   the selected curve's group order.
6. Skip zero; otherwise compute the public point `Q = scalar * G`.

`decimal` uses ASCII decimal with no padding, sign, terminator or newline.
The binary encodings are exactly 4 or 8 bytes (`u32be`, `u32le`, `u64be`,
`u64le`), with zero extension for 64-bit encodings. Input byte order is separate
from the fixed big-endian digest interpretation. A different recipe, including
modulo `(order - 1) + 1`, a different encoding, truncation, or a seeded PRNG,
requires another pack. This mapping is a search hypothesis, not a recommended
key-generation method.

## Record

Each record is `[tag prefix][seed]`. The tag is a 3, 4, 6 or 8 byte prefix of:

```text
SHA256(b"weak-ca-check/point/v1\0" || curve_id || compressed_SEC1_public_point)
```

Curve IDs are one byte: P-256 = 1, P-384 = 2, P-521 = 3. Public points are
validated and encoded in canonical compressed SEC1 form. Seeds use the minimum
1–4 byte width needed for the recipe's highest seed, even if that seed produces
zero. For hash seed-pattern recipes this field stores the pattern index, not the
transformed seed number. Reports include both so a match can be reproduced.
Records are strictly sorted by `(tag, seed)`; duplicate records and seeds
outside the recipe's range are rejected. Different seeds may produce the same
full point and are all retained.

For 100,000 seeds beginning at zero, a default record is **6 bytes**: a 24-bit tag
and a 24-bit seed. One pack occupies 600,000 record bytes plus a small header and
trailer. A 24-bit tag has accidental collisions; for an unrelated public key,
100,000 candidates produce about `100000 / 2^24 = 0.00596` expected tag hits per
pack. Every equal-tag record is examined and its full public point regenerated.
Only a complete point equality becomes a finding. Tag collisions affect speed,
not finding correctness. Wider tags trade space for fewer verifications.

The file is an index of candidate **public keys**, rather than certificate
signatures or certificates. It applies to any certificate containing that key,
regardless of issuer, validity interval or cross-signature. The checker neither
produces forged certificates nor validates signatures or chains.
