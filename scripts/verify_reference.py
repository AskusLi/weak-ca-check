#!/usr/bin/env python3
"""Independent end-to-end check; requires Python cryptography >= 45 (test only)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=root / "target/release/weak-ca-check")
    parser.add_argument("--packs", type=Path, default=root / "dist/starter-100k-v1")
    args = parser.parse_args()
    manifest = json.loads((args.packs / "manifest.json").read_text())
    curves = {"p256": ec.SECP256R1, "p384": ec.SECP384R1, "p521": ec.SECP521R1}
    hash_names = {
        "sha512-224": "sha512_224", "sha512-256": "sha512_256",
        "sha3-256": "sha3_256", "sha3-384": "sha3_384", "sha3-512": "sha3_512",
        "blake2b512": "blake2b", "blake2s256": "blake2s",
    }
    expected = {}
    with tempfile.TemporaryDirectory(prefix="weak-ca-reference-") as directory:
        path = Path(directory)
        for i, asset in enumerate(manifest["assets"]):
            recipe = asset["header"]["recipe"]
            # The final seed proves the distributed range includes its upper endpoint.
            seed = recipe["start"] + recipe["count"] - 1
            assert recipe["encoding"] == "decimal"
            curve = curves[recipe["curve"]]()
            digest = hashlib.new(hash_names.get(recipe["hash"], recipe["hash"]), str(seed).encode()).digest()
            scalar = int.from_bytes(digest, "big") % curve.group_order
            key = ec.derive_private_key(scalar, curve)
            name = f"Synthetic test only: {recipe['curve']}/{recipe['hash']}"
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(i + 1)
                    .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
                    .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .sign(key, hashes.SHA256()))
            (path / f"{i}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            expected[name] = (recipe["curve"], recipe["hash"], seed)
        result = subprocess.run([
            str(args.binary.resolve()), "check", "--small-max", "0", "--pack-dir", str(args.packs),
            "--fail-on-match", str(path),
        ], capture_output=True, text=True)
        assert result.returncode == 2, (result.returncode, result.stderr)
        report = json.loads(result.stdout)
        assert not report["input_errors"]
        assert len(report["findings"]) == len(expected)
        actual = {}
        for finding in report["findings"]:
            cert = finding["certificates"][0]
            evidence = finding["evidence"]
            assert len(evidence) == 1, evidence
            recipe = evidence[0]["recipe"]
            actual[cert["common_name"]] = (finding["curve"], recipe["hash"], evidence[0]["seed"])
        assert actual == expected, (actual, expected)
        print(f"Independent Python/OpenSSL end-to-end verification passed for {len(expected)} distributed recipes.")
        print(result.stderr.strip())


if __name__ == "__main__":
    main()
