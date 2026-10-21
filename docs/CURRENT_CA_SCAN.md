# CCADB public CA scan, 2026-10-21

The offline version 0.2 checker scanned the official CCADB inventory with the
inclusive 1–1,000,000 scalar rule, 39 hash-counter packs and 15 new pattern packs.
All 54 packs used full-point verification. No certificate or trust store was
modified, and no private CA services were contacted.

| Coverage | Count |
| --- | ---: |
| CCADB root/intermediate records | 10,344 |
| Successfully parsed certificate records | 10,329 |
| Supported EC certificate records, including historical entries | 1,772 |
| Distinct EC public points, including historical entries | 1,504 |
| Time-valid EC CA certificates without reported revocation | **1,271** |
| Distinct public points in that current group | **1,139** |
| CA owners in that current group | 62 |
| Current EC CA certificates with included-root metadata | 1,067 |
| Verified weak-key findings in that current group | **0** |

The current group contains 185 roots and 1,086 intermediates: 506 P-256,
742 P-384 and 23 P-521 certificates. All parsed EC public keys use supported
curves. All 8,557 other parsed certificates identify RSA public keys.

“Current” means the Basic Constraints CA flag is set, the scan time is inside
the certificate's validity interval, and CCADB reports either `Not Revoked` or
a blank revocation field. The 185 roots have blank revocation fields; this is
disclosed rather than treated as independent revocation verification. Included
root metadata is a separate source attribute and does not establish a valid
usable chain, application trust, or absence of root-store constraints.

Fifteen records have no published PEM in the downloaded reports. Matching their
fingerprints against the earlier official revoked-intermediate snapshot identifies
all fifteen as RSA-2048 records. They remain errors in the full report, so the
inventory command returns exit status 1. They are not counted as checked keys.
The earlier snapshot has SHA-256
`e018c7daea2262ec7cbbd116b67f9b18e75d9de3d77d47728c3bc9ad5f9180c5`.

The full inventory scan found the same eight known weak P-384 public keys in
historical/revoked records. One also matched the single-bit pattern. No new
distinct weak keys were found. Of 129 truncated-tag hits that failed full-point
verification, none became a finding.

## Sources and reproduction

The [official CCADB resource index](https://www.ccadb.org/resources) describes
the all-certificate inventory and PEM exports. This run used its V5 inventory:

```text
https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5
SHA-256: a8bf8933dc2b5134636ed7ad237a3be3855a2ae7ede4e6fb4c56822defb13646
```

The certificate PEM reports were fetched for the 1990s, 2000s, 2010s and 2020s,
covering every issuance decade in that inventory. The Rust loader verified the
certificate DER SHA-256 fingerprints against the metadata. Source timestamps,
hashes, per-certificate validity, record status and findings are preserved in
the local `reports/current-ca-20261021.json` and its companion full report.

The version 0.2 helper used for this run has been replaced by Rust-native
`import-ccadb` and `check --ccadb` commands. Follow the current README to join
the downloaded inventory and PEM reports, then run the checker against the
unified database. Download a new snapshot to refresh the inputs. The report's
current group depends on the run time. This covers certificates available in this public
CCADB snapshot, not all undisclosed or private CA certificates worldwide.
Zero findings rules out only the reported interval and exact recipes; it is
not proof of adequate key entropy or secure random generation.
