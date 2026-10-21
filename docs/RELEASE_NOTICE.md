# Candidate database safety notice

This database supports recovery of weak candidate private keys. Each stored
record identifies a candidate public point through its recipe and seed index.
If a certificate's public point matches a record, the recipe and index
deterministically reproduce the corresponding private scalar. The table is
therefore security-sensitive research material, not ordinary certificate
metadata.

Use it only for authorized defensive auditing. Treat the database and its
manifest as sensitive, and do not publish match-level reports, seed evidence
or recovered scalars. Share a verified finding with the affected CA and relevant
trust-store program through their incident channels.

The dated CCADB summary records aggregate results only. The full local report
contains private-key recovery evidence and is not included in this package.
This notice describes the capability; it does not remove it or replace an
explicit distribution decision and coordinated disclosure review.
