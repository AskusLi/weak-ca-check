These four public certificates were extracted from CCADB's revoked intermediate
certificate report on 2026-10-21:
https://ccadb.my.salesforce-sites.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV

weak.pem and weak-cross.pem contain the same EM DV TLS CA - G3B public key,
under two issuers. They exercise deduplication and a positive small-scalar check.
historical.pem is an older EM EV TLS CA - G3A public certificate used as a
negative control for the specified interval. rsa.pem exercises explicit
unsupported-algorithm reporting. Revocation and historical metadata come from
that snapshot; the tool does not independently verify live revocation status.

No private-key files are included. The project MIT license applies to its own
code and documentation; these public certificate fixtures retain their issuers'
ownership. See docs/BENCHMARKS.md for the source snapshot's SHA-256.
