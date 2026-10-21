# Hash seed-number patterns

Hash seed patterns transform the stored unsigned 32-bit recipe index into a
numeric seed value. The chosen encoding then converts that number into bytes;
the hash digest is interpreted big endian and reduced modulo the curve order.
The report preserves both the recipe index (`seed`) and transformed numeric
value (`seed_number`). `counter` is the original behavior and is omitted from
serialized recipes to preserve existing pack hashes.

| CLI value | Numeric seed value at index `i` | Decimal / 64-bit domain | 32-bit encoding domain |
| --- | --- | ---: | ---: |
| `counter` | `i` | 0–4,294,967,295 | 0–4,294,967,295 |
| `repeat-byte` | `i * 0x01010101` | 0–255 | 0–255 |
| `repeat-u16be` | `i * 0x00010001` | 0–65,535 | 0–65,535 |
| `single-bit` | `2^i` | 0–63 | 0–31 |
| `low-ones` | `2^(i+1) - 1` | 0–63 | 0–31 |
| `repeat-digit` | `i * 1,111,111,111` | 0–9 | 0–3 |
| `digit-walk` | `1`, `12`, …, `1234567890`, then `9`, `98`, …, `9876543210` | 0–19 | 0–18 |

`repeat-byte` and `repeat-u16be` repeat values across a 32-bit seed word. The
digit classes use decimal digits to define the number; a binary encoding then
encodes that same number as fixed-width big endian or little endian bytes.
Decimal uses unpadded ASCII digits. Zero encodes as the one-character string
`0`.

For example, `seed:repeat-byte` at index 1 produces the numeric seed
`16843009` (`0x01010101`). With decimal encoding and SHA-256, the hashed bytes
are the ASCII string `16843009`. The pack records index 1; a finding reports
both 1 and 16843009.

The `u32be` and `u32le` encodings cap pattern domains where a numeric value
would not fit in 32 bits. `u64be` and `u64le` use all eight bytes, including
leading zero bytes. The `--count` budget is capped at each finite domain, even
when explicitly supplied, so it never requests duplicate values beyond that
class's limit. `--class-count` overrides are strict and reject values above a
finite domain. The default one-million budget therefore enumerates every value
in each finite seed class.

These classes are reproducible search hypotheses. They do not emulate a
specific random-number generator and do not establish that a key came from one
of these procedures.
