#!/usr/bin/env python3
"""Build deterministic starter packs with the Rust binary; Python standard library only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=root / "target/release/weak-ca-check")
    parser.add_argument("--definition", type=Path, default=root / "packs/starter.json")
    parser.add_argument("--output", type=Path, default=root / "dist/starter-100k-v1")
    args = parser.parse_args()
    definition = json.loads(args.definition.read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    binary = str(args.binary.resolve())
    assets = []
    for curve in definition["curves"]:
        for hash_name in definition["hashes"]:
            start = definition["start"]
            count = definition["count"]
            filename = f"{curve}-{hash_name}-{definition['encoding']}-{start}-{start + count - 1}.wkp"
            output = args.output / filename
            subprocess.run([
                binary, "generate", "--curve", curve, "--hash", hash_name,
                "--encoding", definition["encoding"], "--start", str(start),
                "--count", str(count), "--tag-bits", str(definition["tag_bits"]),
                "--output", str(output),
            ], check=True)
            info = json.loads(subprocess.check_output([binary, "inspect", str(output)]))
            assert hashlib.sha256(output.read_bytes()).hexdigest() == info["sha256"]
            assets.append({"file": filename, **info})
    manifest = {"name": definition["name"], "definition": definition, "assets": assets}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    checksums = "".join(f"{a['sha256']}  {a['file']}\n" for a in assets)
    (args.output / "SHA256SUMS").write_text(checksums)
    print(f"Built {len(assets)} packs; {sum(a['file_bytes'] for a in assets):,} bytes", flush=True)


if __name__ == "__main__":
    main()
