#!/usr/bin/env python3
"""Build the five optimized pattern families on all three curves."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=root / "target/release/weak-ca-check")
    parser.add_argument("--counter-count", type=int, default=100000)
    parser.add_argument("--output", type=Path, default=root / "dist/patterns-100k-v1")
    args = parser.parse_args()
    if not 1 <= args.counter_count <= 2**32:
        parser.error("--counter-count must be within 1..2^32")
    binary = str(args.binary.resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    assets = []
    for curve in ["p256", "p384", "p521"]:
        for pattern in ["repeat-byte", "repeat-u16be", "prefix-u32be", "order-minus-counter", "single-bit"]:
            count = {"repeat-byte": 256, "repeat-u16be": 65536,
                     "single-bit": {"p256": 256, "p384": 384, "p521": 521}[curve]}.get(pattern, args.counter_count)
            filename = f"{curve}-{pattern}-0-{count - 1}.wkp"
            output = args.output / filename
            subprocess.run([binary, "generate-pattern", "--curve", curve, "--pattern", pattern,
                            "--count", str(count), "--output", str(output)], check=True)
            info = json.loads(subprocess.check_output([binary, "inspect", str(output)]))
            assert hashlib.sha256(output.read_bytes()).hexdigest() == info["sha256"]
            assets.append({"file": filename, **info})
    manifest = {"name": f"patterns-{args.counter_count}-v1", "counter_count": args.counter_count, "assets": assets}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output / "SHA256SUMS").write_text("".join(f"{a['sha256']}  {a['file']}\n" for a in assets))
    print(f"Built {len(assets)} packs; {sum(a['file_bytes'] for a in assets):,} bytes")


if __name__ == "__main__":
    main()
