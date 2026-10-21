# weak-ca-check

An offline Rust tool for checking public X.509 certificates against explicitly
defined weak elliptic-curve key candidates. One binary and one database file
cover P-256, P-384 and P-521. Certificates can come from any CA.

## Why we are releasing this

A certificate can contain a correctly encoded public key whose private scalar
is a small number or comes from a predictable generator. Checking a certificate's
signature or trust chain does not answer that question. Those weak keys can be
tested by independently reproducing candidate public points.

We started with archived CA certificates and known weak-key controls, then
expanded the checks to the public CCADB inventory. We are releasing the checker,
exact candidate recipes and precomputed database so other people can reproduce
the checks, inspect the method, and test their own certificates. Precomputation
can be shared rather than repeated by every user. The database records both
what was searched and how to regenerate it.

This is bounded research. A match establishes that the complete public key can
be reproduced by a tested candidate. It does not establish how its owner
originally generated the key. No match rules out only the listed recipes and
ranges; it does not prove sufficient entropy or a secure random generator.
The [dated CA scan report](docs/CURRENT_CA_SCAN.md) records the observed results
and coverage limits. We do not infer earlier incidents from unrelated revocations.

## Check a certificate

Extract the binary for your platform and download `all-1m-v1.wkdb` alongside it:

```sh
./weak-ca-check check --cert my-ca.pem --db all-1m-v1.wkdb \
  --output result.json
```

Repeat `--cert` for selected files, or supply a directory as a positional
argument. PEM bundles and DER certificates are supported. Directory traversal
searches `.pem`, `.crt`, `.cer` and `.der` files recursively, without following
directory-entry symlinks. Supply public certificates.

```sh
./weak-ca-check check --cert first.pem --cert second.der --db all-1m-v1.wkdb
./weak-ca-check check certificates/ --db all-1m-v1.wkdb --fail-on-match
```

The default also checks private scalars **1 through 1,000,000, inclusive** using
baby-step giant-step. That rule needs no downloaded table. Use `--small-max 0`
for database-only checks, or select another inclusive bound. `--threads N`
controls worker concurrency. The checker does not contact CA services or alter
certificates, devices or trust stores.

JSON reports include certificate fingerprints, normalized public-key identifiers,
exact evidence for matches, input errors, unsupported algorithms and every
loaded pack's recipe, range and SHA-256. Cross-signed certificates sharing a
public point are checked together, with their source records retained.

**Treat reports with real matches as sensitive.** Their evidence is sufficient
to reproduce the candidate private scalar. Share match-level results through
the affected CA's or trust program's incident channel; use aggregate counts and
the synthetic fixtures for public demonstrations.

Exit status is 0 for a completed check by default. Add `--fail-on-match` to
return 2 when a verified match is found. Status 1 indicates an input or execution
error and takes precedence. A successful exit is not a certificate-security
verdict. Existing output files are protected; use `--force` to replace one.

## Database coverage

The default database contains **303 recipe/curve combinations**: 13 hash
functions, seven seed-number classes and ten scalar-pattern families on each of
three curves. Every hash and curve has one million ordinary counter seeds.
Seed-number patterns are also applied before hashing, including repeated-byte,
repeated-word, bit, ones and decimal-digit sequences. Scalar-pattern recipes
are capped by their own finite domains. Inspect the actual file for exact
coverage:

```sh
./weak-ca-check inspect all-1m-v1.wkdb
./weak-ca-check recipes
```

The hashes are MD5, SHA-1, SHA-224/256/384/512, SHA-512/224 and /256,
SHA3-256/384/512, BLAKE2b-512 and BLAKE2s-256. Legacy hashes are included to
investigate bad key generators. Hash digests are interpreted big endian and
reduced modulo the selected curve's group order; zero is skipped.

Patterns cover repeated bytes, repeated 16-bit and 32-bit words, 16-bit and
32-bit prefixes followed by zeros, values below the group order, values below
an all-ones byte string, a single set bit, consecutive low one bits, and a
single cleared bit in an all-ones scalar mask. [Exact definitions and limits](docs/PATTERNS.md)
are part of the format. Hash seed-number transformations are defined in
[SEED_PATTERNS.md](docs/SEED_PATTERNS.md). These are hypotheses, not a
universal low-entropy test.

A one-million-seed counter pack uses six bytes per candidate: a three-byte
lookup tag and a three-byte seed index. Every tag hit is regenerated and
compared to the **full public point** before a finding is reported. Truncated-tag
collisions cannot establish findings. The unified database embeds the original packs,
their recipes and integrity checksums. Checksums detect corruption; they do
not authenticate a publisher or prove a third-party table is complete. Rebuild
from the recipes to verify its contents.

The [database format](docs/DATABASE.md) and [pack format](docs/FORMAT.md) are
specified for independent implementations. Existing `.wkp` packs remain usable
through `--pack` and `--pack-dir`; multiple `--db` inputs are also supported.
Identical packs are deduplicated.

## Build and extend

Build with Rust 1.94 or later:

```sh
cargo build --release --locked
target/release/weak-ca-check build-db --output all-1m-v1.wkdb
```

The Rust CLI builds every recipe, merges databases, imports downloaded CCADB
data and checks certificates. No separate data-generation runtime is required.
Structured patterns use curve-point recurrences and batch normalization;
hash-counter generation parallelizes independent public-key derivations.

Select a smaller suite, different range or additional seed encodings:

```sh
./weak-ca-check build-db --suite patterns --curve p384 --count 1000000 \
  --output patterns-p384-1m.wkdb
./weak-ca-check build-db --suite hashes --curve p384 --hash sha256 \
  --encoding u32le --count 100000 --output sha256-u32le.wkdb
./weak-ca-check merge-db --db all-1m-v1.wkdb --db sha256-u32le.wkdb \
  --output combined.wkdb
```

Repeat `--curve`, `--hash`, `--encoding`, `--pattern` or `--seed-pattern` to
select combinations. Binary seed encodings are `u32be`, `u32le`, `u64be` and
`u64le`; decimal is the default. Changing an encoding changes the searched
keys. `--count` sets the default candidate budget for each selected class;
finite classes are capped at their domain size.

Raise a specific class without expanding every class:

```sh
./weak-ca-check build-db --count 1000000 \
  --class-count seed:counter=2000000 \
  --class-count scalar:prefix-u32be=5000000 \
  --dry-run
```

Class names are `seed:counter`, `seed:repeat-byte`, `seed:repeat-u16be`,
`seed:single-bit`, `seed:low-ones`, `seed:repeat-digit`, `seed:digit-walk`,
and `scalar:` followed by a scalar-pattern name. Overrides apply to every
selected curve; for seed classes, each selected hash and encoding also gets the
override. Counts outside a finite domain, duplicate overrides, and unselected
or unknown classes are errors before generation begins. `--dry-run` reports all
recipes, total candidate seeds and an upper bound for record bytes.

For hash recipes, the stored seed is the pattern index. Reports also give the
transformed `seed_number` used by the encoding and hash. Definitions and
encoding-specific limits are in [SEED_PATTERNS.md](docs/SEED_PATTERNS.md).
The single-recipe `generate` command accepts `--seed-pattern`; its default
range is capped at 100,000 values. `generate` and `generate-pattern` support
explicit `--start` and `--count` intervals. The builder and checker keep
selected packs in memory; use smaller databases and separate checks when
memory is limited.

## Check the public CA inventory

Download the V5 inventory and PEM reports from the [official CCADB resource index](https://www.ccadb.org/resources).
The example uses all issuance decades present in the recorded 2026 snapshot:

```sh
./weak-ca-check import-ccadb --inventory inventory-v5.csv \
  --pem pems-1990.csv --pem pems-2000.csv --pem pems-2010.csv --pem pems-2020.csv \
  --output joined.csv
./weak-ca-check check --ccadb joined.csv --db all-1m-v1.wkdb --output ca-report.json
```

The importer joins on SHA-256 fingerprint; the checker verifies each parsed
certificate's fingerprint. Missing PEMs and malformed inputs remain explicit
errors. The JSON `current_inventory` view uses exact certificate validity and
reported CCADB revocation status. Blank root revocation fields are counted and
disclosed separately. Included-root metadata does not establish a verified
chain. This inventory covers disclosed public records, rather than every
private CA worldwide.

## Validation and scope

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --release --locked
```

The Rust tests include independent public-point and digest vectors, all 69
original synthetic certificate fixtures, and a seed-pattern CA certificate
that is built into a database and found through the CLI. They also cover
database round trips, corruption, per-class count validation, deduplication,
record widths, recurrence chunk boundaries, interval endpoints, CCADB joins,
output preservation and certificate checks. Tests run offline and require no
external crypto executable or private-key files.

This tool checks public-key candidates. Certificate signature verification,
chain building, expiry enforcement, live revocation, RSA weaknesses and ECDSA
nonce weaknesses are outside its verdict. Unsupported algorithms are reported
separately and are not counted as covered EC keys.

Source code and documentation are MIT licensed. Synthetic fixtures are included
for reproducibility; third-party CA certificate fixtures retain their issuers'
ownership. Binary releases include dependency license notices. Measurements
and platform-validation limits are recorded in [the benchmark notes](docs/BENCHMARKS.md).
