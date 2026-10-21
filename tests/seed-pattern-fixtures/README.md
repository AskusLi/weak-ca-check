`seed-pattern-repeat-byte-p384.pem` is a synthetic CA certificate used to test
end-to-end detection. Its P-384 public key was derived from SHA-256 of the
base-10 seed number `16843009`, which is the repeated-byte value for pattern
index 1. The matching test builds all 256 candidates in that class, checks the
certificate, and verifies the reported pattern index and seed number. The
fixture contains only the public certificate; its throwaway signing key was not
retained.
