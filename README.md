# weak-ca-check

Check certificates for keys made from small numbers or predictable patterns.
Written in Rust. Works offline with P-256, P-384 and P-521 public keys.

**TL;DR:** We checked 1,504 distinct EC CA public keys against about **54 million
low-entropy key candidates**, plus private-key values from 1 through 1,000,000.
The only matches were the **eight already-revoked eMudhra keys**. No new weak
keys were found. These are the results of our [2026-10-21 CCADB scan](docs/CURRENT_CA_SCAN.md).

Generating the table took **25 minutes on a nine-year-old desktop CPU**:
an Intel Core i7-7700, [released in early 2017](https://www.intel.com/content/www/us/en/products/compare.html?productIds=97128%2C97147).
The table is **306 MiB**. Checking the full CA inventory took **7.51 seconds**
with the table already in the filesystem cache. [Measured times and hardware](docs/BENCHMARKS.md).

## The idea

The inspiration comes from rainbow tables used for Wi-Fi password testing:
do the expensive work once, save the results, and reuse them. Here, we generate
public keys from predictable inputs and put them in a compact lookup table.
Checking another certificate means looking up its public key instead of
generating all those candidates again.

A long key can still come from a small number of guesses. Hashing a number
between 0 and 999,999 may produce a long, random-looking value, but there are
still only a million inputs to try. The same goes for repeated bytes, simple
bit patterns and other predictable choices.

The goal is to make those checks easy to run and easy to extend. Build a table
once, then use it to check a single certificate or a whole collection. It works
with certificates from any CA, or your own test certificates.

## Try a known weak test certificate

Requires Rust 1.94 or later. From the repository directory, this example builds
256 candidates and checks a synthetic certificate included in the repository:

```sh
cargo build --release --locked
./target/release/weak-ca-check build-db --suite hashes \
  --curve p384 --hash sha256 --seed-pattern repeat-byte \
  --output dist/demo.wkdb
./target/release/weak-ca-check check --small-max 0 --db dist/demo.wkdb \
  --cert tests/seed-pattern-fixtures/seed-pattern-repeat-byte-p384.pem \
  --output reports/demo.json --fail-on-match
```

The check should find one match and exit with status **2**. The test suite
covers this path too:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --release --locked
```

## Build and run

Requires Rust 1.94 or later. Run these commands from the repository directory:

```sh
cargo build --release --locked
./target/release/weak-ca-check check --cert my-ca.pem
```

That checks for private keys with values from 1 through 1,000,000. It uses
baby-step giant-step and needs no database. Results go to standard output as
JSON.

The default hash and pattern database took about **25 minutes** to build on an
i7-7700 and uses **306 MiB**. It is generated locally and is not committed to
this repository. To build it and check a certificate:

```sh
./target/release/weak-ca-check build-db --dry-run
./target/release/weak-ca-check build-db --output dist/all-1m-v1.wkdb
./target/release/weak-ca-check check --cert my-ca.pem \
  --db dist/all-1m-v1.wkdb --output reports/my-ca.json
```

`--dry-run` shows the recipes, candidate counts and an estimate of the table
entry sizes without building anything.

Repeat `--cert` to check several files, or pass a directory:

```sh
./target/release/weak-ca-check check --cert first.pem --cert second.der \
  --db dist/all-1m-v1.wkdb
./target/release/weak-ca-check check certificates/ \
  --db dist/all-1m-v1.wkdb --output reports/certificates.json
```

PEM bundles and DER certificates are supported. Directory scans include
`.pem`, `.crt`, `.cer` and `.der` files in subdirectories. Use `--small-max 0`
to run only the database checks, and `--threads N` to set the worker count.
Existing output files are kept unless you pass `--force`.

## What goes in the table?

The default build has **303 combinations of recipes and curves**, covering
**53,969,517 candidate inputs** across three curves. Some candidates
overlap, so this is not a count of unique keys.

| Candidates | Default coverage |
| --- | --- |
| Hashes of counter seeds | Seeds 0–999,999 for each hash and curve |
| Hashes of patterned seeds | Repeated bytes and words, single bits, runs of ones, repeated digits and digit sequences |
| Direct key patterns | Repeated bytes and words, prefixes followed by zeros, bit patterns, and values near the curve order or an all-ones value |

The 13 hashes are MD5, SHA-1, SHA-224/256/384/512, SHA-512/224 and /256,
SHA3-256/384/512, BLAKE2b-512 and BLAKE2s-256. Counter seeds use decimal text
by default. Binary encodings are also available.

For a million-seed recipe, each table entry takes six bytes: three for a lookup
tag and three for the seed index. A tag match is only a lead. The checker
regenerates the candidate and compares the full public key before reporting a
match. The database also records the recipes and checksums needed to rebuild it.

## Change the search size

`--count` sets the number of candidate seeds per class. Classes with fewer
possible values stop at their limit. To build a smaller database:

```sh
./target/release/weak-ca-check build-db --count 100000 \
  --output dist/all-100k.wkdb
```

Use `--class-count` to increase specific classes. For example, plan two million
counter seeds per hash and curve, and five million 32-bit prefix patterns:

```sh
./target/release/weak-ca-check build-db \
  --class-count seed:counter=2000000 \
  --class-count scalar:prefix-u32be=5000000 --dry-run
```

Replace `--dry-run` with `--output dist/expanded.wkdb` to build it. Overrides
above a class's limit are rejected.

You can also select curves, hashes, seed patterns and direct key patterns.
`recipes` lists the choices; `build-db --help` lists the options. Multiple
databases can be checked together with repeated `--db` arguments, or combined
with `merge-db`.

## Reading the results

A match means the checker reproduced the certificate's full public key from
one of the candidates. No match means those candidates did not work. It does
not prove that the key was generated safely.

By default, a completed check exits with status **0**, even if it finds matches.
`--fail-on-match` changes that to **2**. Input or execution errors return **1**
and take precedence. The report lists unsupported algorithms and input errors.

This checks how a public key might have been generated. It does not verify
certificate signatures, build trust chains, check live revocation, or test
RSA keys or ECDSA signing nonces.

**Keep reports with real matches private.** The recipe and seed can reproduce
the private key. The database and its manifest can also help recover matching
keys. This repository is private; the generated database and full scan reports
remain local. See the [distribution notice](docs/RELEASE_NOTICE.md).

## How it was built

We gave [**Operator Develop**](https://askus.li/operator) the idea and the objective: make it easy to check
certificates for low-entropy keys using reusable lookup tables. We then used
[**Operator Review**](https://askus.li/operator) to look for errors and ways to improve performance, and
used its findings to improve the code.

## More details

- [Full CA scan results and coverage](docs/CURRENT_CA_SCAN.md)
- [Build times, scan times and database sizes](docs/BENCHMARKS.md)
- [Seed patterns and encodings](docs/SEED_PATTERNS.md)
- [Direct key patterns](docs/PATTERNS.md)
- [Database format](docs/DATABASE.md) and [individual pack format](docs/FORMAT.md)

Source and documentation: [MIT license](LICENSE). Third-party CA certificate
fixtures retain their issuers' ownership.
