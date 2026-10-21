# weak-ca-check

A fast, offline Rust checker for explicitly defined weak elliptic-curve keys in
public X.509 certificates. It checks small private scalars and reusable packs of
hash-counter candidates. It accepts certificates from any CA; it does not use a
CA-name allowlist.

## Run

Use a precompiled binary with the starter packs, or build with Rust 1.94+:

```sh
cargo build --release --locked
target/release/weak-ca-check check certificates/ --output report.json
```

The default checks scalars **1 through 1,000,000, inclusive**, on P-256, P-384
and P-521. Baby-step giant-step uses about the square root of the interval per
distinct target key and a shared lookup per curve. There is no million-entry
download for this rule.

Add the extracted starter pack directory:

```sh
weak-ca-check check --pack-dir starter-100k-v1 certificates/ --output report.json
```

Paths may be PEM bundles, DER certificates, or directories searched recursively
for `.pem`, `.crt`, `.cer` and `.der` files. Directory traversal does not follow
symlinks. Supply public certificates, rather than private-key files. Cross-signed
certificates sharing one public point are checked once, while their fingerprints
and source records remain in the finding.

To test one specific certificate, use the explicit `--cert` option (also
available as `--certificate`). Repeat it to test several chosen files:

```sh
weak-ca-check check --cert my-ca.pem --pack-dir starter-100k-v1 \
  --pack-dir patterns-100k-v1 --fail-on-match --output result.json
```

This checks the default million-scalar interval plus both pack directories.
Use `--small-max 0` to select only the supplied packs. The JSON contains exact
recipe/seed evidence for matches and a per-certificate EC inventory, including
validity timestamps and normalized public-point identifiers.

For a downloaded CCADB revoked-intermediate CSV:

```sh
weak-ca-check check --ccadb revoked-intermediates.csv \
  --pack-dir starter-100k-v1 --output report.json
```

The CSV loader verifies each parsed certificate against the CSV SHA-256
fingerprint. Missing PEM fields and malformed records are reported as input
errors and produce exit status 1. RSA and other unsupported curves are listed
separately; they are not counted as checked EC keys. The checker does not fetch
network resources or modify trust stores, routers or certificates.

Use `--small-max 0` for pack-only checks. Repeat `--pack FILE` or
`--pack-dir DIRECTORY` for multiple inputs. `--threads N` controls parallelism.
`--fail-on-match` returns 2 for verified findings, allowing CI to reject weak
keys. Exit status 1 takes precedence when an input error occurs; otherwise the
default exit status is 0 even when the JSON contains findings.

## Starter packs and custom recipes

The `starter-100k-v1` set contains **39 packs**: 13 hash functions on each of three
curves, with decimal ASCII seeds **0 through 99,999**. Each pack occupies about
600 KB; the complete record payload is 23.4 MB. The supported hashes are MD5,
SHA-1, SHA-224/256/384/512, SHA-512/224 and /256, SHA3-256/384/512, BLAKE2b-512
and BLAKE2s-256. Weak legacy hashes are included to investigate bad generators.

Each recipe hashes the encoded seed, interprets the digest as a big-endian
integer, reduces it modulo the curve order, skips zero, and derives the public
point. The complete recipe is embedded in the pack. These 13 hashes are an
explicit supported set; they do not represent every hash function or generator.

```sh
weak-ca-check generate --curve p384 --hash sha256 --encoding decimal \
  --start 0 --count 100000 --output p384-sha256-decimal-0-99999.wkp
weak-ca-check inspect p384-sha256-decimal-0-99999.wkp
weak-ca-check recipes
```

Generate the full starter set from source, with Python's standard library:

```sh
python3 scripts/build_starter.py
```

The default output is `dist/starter-100k-v1/`, including a manifest and SHA-256
checksums. Build one million seeds with `--count 1000000`, or partition ranges
with `--start` and `--count`. Other encodings are `u32be`, `u32le`, `u64be` and
`u64le`. Changing an encoding or scalar mapping changes which keys are covered.
The builder currently keeps a pack's records in memory; partition large ranges
to limit memory. Packs are release assets and are excluded from Git history.

## Fast pattern generators

Version 0.2 adds five scalar pattern families: repeated bytes, repeated 16-bit
words, a 32-bit prefix followed by zeros, values just below the group order,
and a single set bit. These generators use point additions or doublings and
batch normalization. They avoid a separate full scalar multiplication for
every candidate. All lookup hits still require full-point verification.

```sh
weak-ca-check generate-pattern --curve p384 --pattern prefix-u32be \
  --count 1000000 --output prefix-p384-1m.wkp
weak-ca-check check --cert my-ca.pem --pack prefix-p384-1m.wkp
python3 scripts/build_patterns.py
```

The pattern builder produces 15 packs in `dist/patterns-100k-v1`, about 4.6 MB.
It covers the complete repeated-byte, repeated-word and single-bit domains;
the prefix and order-minus-counter families use seeds 0–99,999 by default.
Use `--counter-count 1000000 --output dist/patterns-1m-v1` for wider counter
ranges. [Pattern definitions and limits](docs/PATTERNS.md) specify every mapping.

## Check the public CA inventory

The following helper downloads and caches the official CCADB root/intermediate
inventory and certificate PEM reports, joins them by SHA-256 fingerprint, then
invokes the offline Rust checker:

```sh
python3 scripts/check_ccadb.py --pack-dir dist/starter-100k-v1 \
  --pack-dir dist/patterns-100k-v1 --output reports/current-ca.json
```

The summary separates time-valid CA certificates without reported revocation
from historical records. It preserves source hashes, missing-certificate
errors and a full report. Blank root revocation fields are disclosed separately.
Root-store metadata is not a chain validation. The download covers CCADB's
public inventory rather than every private or undisclosed CA worldwide.
Cached files are reused; `--refresh` fetches a new snapshot.

## Compact lookup with exact verification

A default record contains a **3-byte lookup tag plus a 3-byte seed** for the
100,000-seed range. The checker binary-searches the sorted tags, regenerates
every matching candidate, then compares the **full public point**. A truncated
tag alone never establishes a finding. Packs include corruption checksums;
rebuilding from the embedded recipe verifies their contents. Checksums alone
do not authenticate a publisher. [The format specification](docs/FORMAT.md)
defines the encoding and collision behavior.

## What a result establishes

A finding means the certificate's full public key exactly matches a tested
small scalar or recipe candidate. It does not establish the original key
generation procedure. A negative result rules out only the reported interval
and recipes; it does **not** prove high entropy, secure randomness, or absence
of another predictable generator. Entropy cannot be measured from one public
point by this lookup.

This is a public-key weakness check. It does not validate certificate signatures,
trust chains, expiry, or current revocation status. Revocation dates in CSV
results are reported source metadata. RSA key weaknesses and ECDSA nonce or
signature weaknesses require different checks.

## Validation and performance

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --release --locked
```

Tests cover independent Python/OpenSSL point vectors, all 13 hash digest
vectors, every supported curve, inclusive interval boundaries, pack corruption,
variable record widths, cross-signature deduplication and deliberate tag
collisions. For an independent end-to-end test of every distributed recipe,
install Python `cryptography>=45` in a test environment, then run:

```sh
python3 scripts/verify_reference.py
```

It constructs temporary synthetic public test certificates using Python/OpenSSL
at the final seed of each pack and checks the Rust CLI's exact findings. It
does not write private-key files or install certificates.

See [measured results and dataset coverage](docs/BENCHMARKS.md). Source code and
documentation are MIT licensed; public certificate fixtures retain their
issuers' ownership.
