# Measured results, 2026-10-21

Host: Intel Core i7-7700, 4 cores / 8 logical CPUs, Linux x86-64. Rust 1.94.0,
release profile, thin LTO, one codegen unit, generic target CPU. The distributed
Linux binary uses `x86_64-unknown-linux-musl` and is statically linked. Default
Rayon thread count: 8. These measurements are observations on this host, rather
than promises for other hardware.

The table gives the median of seven complete process runs, with warm filesystem
caches. Timing includes input parsing, pack integrity/ordering validation where
applicable, key checks, and JSON report serialization/capture. The first two
cases use no packs. The hash-only case disables the small-scalar rule.

| Input / rules | Parsed certificates | Distinct supported EC keys | Median seconds |
| --- | ---: | ---: | ---: |
| eMudhra historical/incident set, scalars 1–1,000,000 | 51 | 24 | 0.020 |
| Revoked CCADB snapshot, scalars 1–1,000,000 | 2,946 | 298 | 0.237 |
| Same snapshot, small scalars + all 39 starter packs | 2,946 | 298 | 0.602 |
| Same snapshot, all 39 starter packs only | 2,946 | 298 | 0.483 |

The earlier independent Python/OpenSSL exhaustive one-million-scalar check on
the same 51-certificate eMudhra set took 476.22 seconds. The Rust result agreed
exactly on all 16 matching certificate fingerprints and eight distinct weak
keys. The speed difference includes a major **algorithm change**: exhaustive
scalar multiplication was replaced with baby-step giant-step and batch point
normalization. It must not be attributed to the programming language alone.

## Dataset and coverage

Source: [CCADB revoked intermediates with PEM](https://ccadb.my.salesforce-sites.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV),
downloaded on 2026-10-21. SHA-256:

```text
e018c7daea2262ec7cbbd116b67f9b18e75d9de3d77d47728c3bc9ad5f9180c5
```

The snapshot contains 2,961 rows from 71 CA owners. Fifteen rows have no PEM
certificate (`PEM Info` contains only quotes); CCADB lists them as RSA-2048
records. They remain input errors in the report, so these dataset runs correctly
return exit status 1. Of 2,946 successfully parsed certificates, 357 contain
supported EC keys: 114 P-256, 239 P-384 and four P-521 certificates. Deduplication
leaves 298 EC public points. The other 2,589 parsed certificates are explicitly
outside this EC check. Reported coverage must not be described as an RSA audit
or a survey of all currently trusted CAs.

The million-scalar check found eight weak P-384 public keys across 16
certificates: eight eMudhra records and eight Sectigo cross-signatures. They
correspond to the known incident controls. The older eMudhra group contains
16 distinct EC keys; none matched this interval. No additional small-scalar
matches appeared elsewhere in this snapshot. No hash-counter recipe matches
appeared. The pack lookup encountered 30 truncated-tag collisions across the
298 targets and rejected all of them by full-point verification.

These are bounded results. A negative result does not establish sufficient
entropy, or rule out other scalar mappings, encodings, PRNGs, curves or ranges.
The snapshot and reported revocation dates do not independently establish when
a key became vulnerable or whether an older CA compromise occurred.

## Starter pack costs

`starter-100k-v1` contains 39 recipe/curve combinations, each enumerating decimal
seeds 0–99,999. Together they hold 3.9 million records in **23,411,166 bytes**,
excluding the manifest and external checksums. Each record is six bytes.
The P-384/SHA-256 pack is 600,285 bytes. Its initial build took 4.030 seconds;
the sum of individual generation times for the complete set was 134.371
seconds. A concurrent compiler ran during part of generation; this is not an
isolated throughput benchmark. Individual pack times ranged from 1.104 to
6.593 seconds across the different curves/hashes.

The generator emits deterministic packs; generation time is deliberately not
embedded in the manifest or pack. The manifest records exact recipes, record
counts, file sizes and whole-file SHA-256 checksums.

## Independent verification

All 13 Rust unit tests pass for both the native Linux and static musl builds.
The tests include Python/OpenSSL reference points on all three curves and
Python `hashlib` reference digests for all supported hash functions.
The historical reference harness additionally generated 39 temporary synthetic
test certificates using Python `cryptography` 50.0.0, one at seed 99,999 of
each starter recipe. Both compiled binaries reported exactly the expected
39 recipe/seed matches. No private-key files were written.

macOS and Windows release jobs are provided in the workflow. They have not
been executed locally, and no binaries for those platforms are claimed here.

## Version 0.2 additions

The optimized P-384 prefix-pattern generator produced 99,999 nonzero candidates
from 100,000 seeds in 0.078 seconds. A million-seed run produced 999,999
candidates in 1.076 seconds and occupied 6,000,246 bytes. The larger run shared
the host with other validation work, so this is an indicative wall time rather
than an isolated throughput measurement. Pattern recurrence enables these
speeds; they do not apply to arbitrary hash-counter generators.

The new 15-pack pattern bundle occupies 4,595,267 bytes, bringing both bundles
to 28,006,433 bytes. All 18 unit tests pass. Independent Python/OpenSSL checks
cover all 54 distributed recipes and the explicit `--cert` CLI option, including
overlapping recipes that produce the same public point. Rebuilding the original
P-384/SHA-256 100k hash pack reproduced its original whole-file SHA-256 exactly:
`4838cc8a89276ba2c53d3bf5c9c3c7986e4b2d2fa665bf342d9f629f16b52321`.

See [the current public CA scan](CURRENT_CA_SCAN.md) for the broader inventory
coverage and bounded results.

## Version 0.3 production layout

The production CLI, database builders, CCADB importer, release-license helper
and tests are Rust. The earlier scripting helpers were removed. Static public
certificate fixtures retain the independent reference values without a runtime
dependency on their generation environment.

The unified database contains 69 packs: 39 hash-counter combinations and 30
pattern combinations. It holds 5,497,449 candidate records in 32,611,938 bytes,
including the database index and all embedded pack metadata. Exact sizes,
counts and checksums are emitted by `inspect`; this was the prior local database
layout before the 0.4 all-1m-v1 expansion.

## Version 0.4 full default database

The default all-1m-v1 plan contains 303 recipes and 53,969,517 candidate seeds.
On the host above, generating and writing the complete unified database took
1,500.13 seconds (25 minutes) and peaked at 399,460 KiB RSS. The resulting file
is 320,953,916 bytes; its SHA-256 is:

```text
9565c2ab6369ff9e2313a411d5d0d4a2ba1af47b9323d3df1c77c80fae4e7b7b
```

The matching `inspect` manifest is 170,059 bytes with SHA-256
`47516ad9db3ba38b9795556cbf5ded26d0b02df74f3eb53b620b0026b3c7d3bf`.
The timed build used this command after the release binary had been compiled:

```sh
/usr/bin/time -f '%e seconds real; %M KiB peak RSS' \
  -o /tmp/weak-ca-v04-build.time \
  target/release/weak-ca-check --threads 8 build-db \
  --output dist/all-1m-v1.wkdb
```

The complete process to scan the 10,344-row current CCADB snapshot with this
database took 7.51 seconds and peaked at 354,772 KiB RSS. Its file contents were
in the local filesystem cache. The scan covered 10,329 parsed certificates,
1,504 distinct supported EC public keys and all 303 recipes. It found no match
in the time-valid, non-revoked group and repeated the eight known weak P-384
matches among records reported revoked. Fifteen missing PEM records remained
input errors. The measured command was:

```sh
/usr/bin/time -f '%e seconds real; %M KiB peak RSS' \
  -o /tmp/weak-ca-v04-scan-final.time \
  target/release/weak-ca-check --threads 8 check \
  --force --ccadb path/to/joined-native.csv --db dist/all-1m-v1.wkdb \
  --output current-ca-20261021-v04.json
```

It printed `10329 certificates; 1504 distinct supported EC keys; 1504
covered; 8 weak-key matches; 15 input errors` and returned status 1 for those
input errors. The classification timestamp and input hashes are recorded in
[the scan report](CURRENT_CA_SCAN.md).

The full per-certificate output contains private-key recovery evidence and is
kept local. Only aggregate findings are recorded here.
