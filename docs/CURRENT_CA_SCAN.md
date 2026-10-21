# CCADB public CA scan, 2026-10-21

Version 0.4 scanned the CCADB V5 inventory with the inclusive 1–1,000,000
small-scalar check and the complete 303-recipe database. The database covers the
default hash-seed and scalar-pattern classes on P-256, P-384 and P-521. Every
one of the 1,504 distinct supported EC public keys in the parsed inventory was
covered by the small-scalar check and the database. The scan found no weak key
in the time-valid, non-revoked CCADB group. It found eight distinct weak P-384
keys among records CCADB reports as revoked; those are the previously known
historical matches. One also overlaps a scalar-pattern recipe. No new distinct
weak keys were found by the expanded recipe set.

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
| Distinct historical weak P-384 keys | **8** |
| Candidate recipes checked | 303 |

The current group contains 185 roots and 1,086 intermediates: 506 P-256,
742 P-384 and 23 P-521 certificates. All parsed EC public keys use supported
curves. All 8,557 other parsed certificates identify RSA public keys.

“Current” means the Basic Constraints CA flag is set, the scan time is inside
the certificate's validity interval, and CCADB reports either `Not Revoked` or
a blank revocation field on a root record. The 185 roots have blank revocation
fields; this is disclosed rather than treated as independent revocation
verification. Included-root metadata is a separate source attribute and does
not establish a valid usable chain, application trust, or absence of
root-store constraints.

Fifteen records have no published PEM in the downloaded reports. Matching their
fingerprints against the earlier official revoked-intermediate snapshot
identifies all fifteen as RSA-2048 records. They remain input errors in the full
scan and are not counted as checked keys. The earlier snapshot has SHA-256
`e018c7daea2262ec7cbbd116b67f9b18e75d9de3d77d47728c3bc9ad5f9180c5`.

The complete process took 7.51 seconds and peaked at 354,772 KiB RSS on the host
described in [the benchmark notes](BENCHMARKS.md). The input database had just
been built, checksummed and inspected, so its file contents were in the local
filesystem cache. The checker itself reports 0.732 seconds after loading and
validating its inputs. The full inventory scan returned exit status 1 because
of the fifteen missing PEM records; the report preserves those errors.

The full per-certificate report is a local research artifact and contains
private-key recovery evidence for the historical matches. It is not part of
the source tree or release package. This summary intentionally omits that
evidence.

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
hashes, validity, record status and findings are preserved in the local
research report. To refresh the inventory, download a new snapshot and follow
the current README to join the metadata and PEM reports before running the
checker. The current group depends on the run time. This scan covers public
CCADB records, not all undisclosed or private CA certificates worldwide.

Zero findings in the current group rule out only the reported scalar interval
and exact recipes. They do not prove adequate key entropy or secure random
generation. The checker does not verify certificate signatures, build trust
chains, or independently query revocation services.
