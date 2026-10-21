Synthetic, self-signed CA certificates for independent end-to-end test vectors.
They are test fixtures, with no relationship to any trusted CA or live service.

Each public key was independently calculated with OpenSSL through cryptography
50.0.0 and standard hash implementations. index.json records the exact recipe,
final seed, compressed public point and certificate fingerprint. Generation
constructed scalar bytes separately from the Rust recipe implementation.

The Rust tests consume these static public fixtures directly. No scripting
runtime, network access, external crypto binary or private-key file is needed.
The committed data covers all three curves and all 69 default recipe/curve
combinations. Only public certificates and reference values are included.
