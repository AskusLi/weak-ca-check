#!/usr/bin/env python3
"""Collect dependency license texts from Cargo's downloaded sources for releases."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target")
    parser.add_argument("--output", type=Path, default=Path("dist/THIRD_PARTY_NOTICES.txt"))
    args = parser.parse_args()
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if args.target:
        command += ["--filter-platform", args.target]
    metadata = json.loads(subprocess.check_output(command))
    output = ["THIRD-PARTY DEPENDENCY LICENSE NOTICES\n\nGenerated from Cargo.lock dependency sources.\n"]
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["name"] == "weak-ca-check":
            continue
        directory = Path(package["manifest_path"]).parent
        files = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(
            ("LICENSE", "LICENCE", "COPYING", "NOTICE")))
        if not files and package["name"] == "asn1-rs-impl" and package["version"] == "0.2.0":
            # This published subcrate omits its repository-root license file.
            # Upstream LICENSE-MIT Git blob: 290e7b9be19d39a81c8eb24c75a6b5f1e57fea71
            files = [Path(__file__).parent / "licenses/asn1-rs-impl-MIT.txt"]
        if not files:
            raise RuntimeError(f"No license text for {package['name']} {package['version']}")
        output.append(f"\n{'=' * 72}\n{package['name']} {package['version']} ({package['license']})\n")
        for path in files:
            output.append(f"\n--- {path.name} ---\n{path.read_text(errors='replace')}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(output))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
