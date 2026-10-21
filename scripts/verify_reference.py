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
    expected_points = {}
    def scalar_for(recipe, seed, curve):
        mapping = recipe["mapping"]
        width = (curve.key_size + 7) // 8
        if mapping == "digest-be-mod-order-v1":
            assert recipe["encoding"] == "decimal"
            digest = hashlib.new(hash_names.get(recipe["hash"], recipe["hash"]), str(seed).encode()).digest()
            scalar = int.from_bytes(digest, "big")
        elif mapping == "repeat-byte-mod-order-v1":
            scalar = int.from_bytes(bytes([seed]) * width, "big")
        elif mapping == "repeat-u16be-mod-order-v1":
            scalar = int.from_bytes(seed.to_bytes(2, "big") * (width // 2), "big")
        elif mapping == "prefix-u32be-mod-order-v1":
            scalar = int.from_bytes(seed.to_bytes(4, "big") + bytes(width - 4), "big")
        elif mapping == "order-minus-counter-v1":
            scalar = curve.group_order - seed
        elif mapping == "single-bit-v1":
            scalar = 1 << seed
        else:
            raise ValueError(f"Unknown mapping {mapping}")
        return scalar % curve.group_order

    def point_for(recipe, seed):
        curve = curves[recipe["curve"]]()
        return ec.derive_private_key(scalar_for(recipe, seed, curve), curve).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

    with tempfile.TemporaryDirectory(prefix="weak-ca-reference-") as directory:
        path = Path(directory)
        for i, asset in enumerate(manifest["assets"]):
            recipe = asset["header"]["recipe"]
            # The final seed proves the distributed range includes its upper endpoint.
            seed = recipe["start"] + recipe["count"] - 1
            curve = curves[recipe["curve"]]()
            scalar = scalar_for(recipe, seed, curve)
            key = ec.derive_private_key(scalar, curve)
            name = f"Synthetic test only: {recipe['curve']}/{recipe.get('hash', recipe['mapping'])}"
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(i + 1)
                    .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
                    .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .sign(key, hashes.SHA256()))
            (path / f"{i}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            expected[name] = (recipe, seed)
            expected_points[name] = point_for(recipe, seed)
        result = subprocess.run([
            str(args.binary.resolve()), "check", "--small-max", "0", "--pack-dir", str(args.packs),
            "--fail-on-match", str(path),
        ], capture_output=True, text=True)
        assert result.returncode == 2, (result.returncode, result.stderr)
        report = json.loads(result.stdout)
        assert not report["input_errors"]
        assert len(report["findings"]) == len(set((expected[n][0]['curve'], p) for n, p in expected_points.items()))
        actual = {}
        for finding in report["findings"]:
            for cert in finding["certificates"]:
                name = cert["common_name"]
                assert any((e["recipe"], e["seed"]) == expected[name] for e in finding["evidence"])
                for evidence in finding["evidence"]:
                    assert evidence["recipe"]["curve"] == finding["curve"]
                    assert point_for(evidence["recipe"], evidence["seed"]) == expected_points[name]
                actual[name] = expected[name]
        assert actual == expected, (actual, expected)
        print(f"Independent Python/OpenSSL end-to-end verification passed for {len(expected)} distributed recipes.")
        print(result.stderr.strip())
        single = subprocess.run([str(args.binary.resolve()), "check", "--small-max", "0",
                                 "--pack-dir", str(args.packs), "--cert", str(path / "0.pem"),
                                 "--fail-on-match"], capture_output=True, text=True)
        assert single.returncode == 2, single.stderr
        assert json.loads(single.stdout)["input_certificates"] == 1
        print("Specific-certificate --cert CLI verification passed.")


if __name__ == "__main__":
    main()
