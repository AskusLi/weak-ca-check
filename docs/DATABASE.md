# Unified database format, version 1

A `.wkdb` file contains complete, unchanged `.wkp` packs. All integers below
are unsigned big endian. Every pack and the complete database are validated
before any certificate result is emitted.

| Field | Bytes |
| --- | ---: |
| ASCII `WKDB0001` | 8 |
| JSON index byte length | 4 |
| UTF-8 JSON index | variable, at most 16 MiB |
| Embedded packs | sum of indexed pack lengths |
| SHA-256 of all preceding bytes | 32 |

The index object contains `version: 1` and a `packs` array with 1–10,000 entries.
Each entry has `offset`, `bytes` and a lowercase hexadecimal `sha256`. Offsets are relative to the first
payload byte. Pack lengths include each pack's own header and checksum trailer.
The SHA-256 identifies the entire embedded pack including that trailer.
Unknown JSON fields are rejected.

Entries must cover the entire payload contiguously, beginning at offset zero.
Overlaps, gaps, arithmetic overflow, duplicate pack identities, invalid digest
lengths and trailing bytes are rejected. Each embedded pack's SHA-256 must
match the index, and its own recipe, record ordering, length and checksum must
pass the [pack reader](FORMAT.md). The final trailer validates the index and
payload together. `inspect` reports the SHA-256 of the whole database, including
its trailer, and describes every embedded recipe.

The writer sorts unique packs by their SHA-256 string. Identical packs supplied
through different paths or databases are retained once. Different recipes or
overlapping seed ranges remain distinct, because those metadata are part of
the embedded pack's identity. Given the same pack bytes, merged output is
deterministic and independent of input order.

The reader streams from the file into separately owned packs, avoiding a
second whole-database buffer. All selected packs remain in memory for checking.
Only validated lookup hits are re-derived; a full curve-point equality is
required for a finding. A database checksum is a corruption check, not publisher
authentication or proof of exhaustive candidate generation.

Writes use a temporary file in the destination directory and synchronize it
before publication. Default publication uses a hard link so an existing output
is never overwritten. `--force` permits replacement by rename. Filesystems
that do not support the required operation return an error. Successful
publication makes a complete file visible atomically; it does not promise
directory-entry durability across a power failure.
