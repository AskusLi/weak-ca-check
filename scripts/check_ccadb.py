#!/usr/bin/env python3
"""Download/cache the CCADB inventory and public CA certificates, then audit offline."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=root / "target/release/weak-ca-check")
    parser.add_argument("--cache", type=Path, default=root / "datasets/ccadb-current")
    parser.add_argument("--pack-dir", action="append", type=Path, default=[])
    parser.add_argument("--small-max", type=int, default=1000000)
    parser.add_argument("--output", type=Path, default=root / "reports/ccadb-current-summary.json")
    parser.add_argument("--refresh", action="store_true", help="Replace the cached snapshot; otherwise reuse it")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sources_file = args.cache / "sources.json"
    previous = {s['file']: s for s in json.loads(sources_file.read_text())} if sources_file.exists() else {}
    sources = []

    def get(filename, url):
        path = args.cache / filename
        retrieved = None
        if args.refresh or not path.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
            path.write_bytes(data)
            retrieved = datetime.now(timezone.utc).isoformat()
        else:
            data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        cached = previous.get(filename, {})
        if not retrieved and cached.get('sha256') == digest:
            retrieved = cached.get('retrieved_utc')
        sources.append({'file': filename, 'url': url, 'bytes': len(data), 'sha256': digest, 'retrieved_utc': retrieved})
        return path

    base = 'https://ccadb.my.salesforce-sites.com/ccadb/'
    inventory = get('all-certificate-records-v5.csv', base + 'AllCertificateRecordsCSVFormatV5')
    with inventory.open(newline='') as handle:
        rows = list(csv.DictReader(handle))
    decades = sorted({int(row['Valid From (GMT)'][:4]) // 10 * 10 for row in rows})
    pems = {}
    for decade in decades:
        path = get(f'certificate-pems-{decade}.csv', base + f'AllCertificatePEMsCSVFormat?NotBeforeDecade={decade}')
        with path.open(newline='') as handle:
            for row in csv.DictReader(handle):
                text = row['X.509 Certificate (PEM)']
                if '-----BEGIN CERTIFICATE-----' not in text:
                    continue
                start = text.index('-----BEGIN CERTIFICATE-----')
                end = text.index('-----END CERTIFICATE-----', start) + len('-----END CERTIFICATE-----')
                fp = row['SHA-256 Fingerprint'].replace(':', '').lower()
                pem = text[start:end]
                if fp in pems and pems[fp] != pem:
                    raise ValueError(f'Conflicting certificate data for {fp}')
                pems[fp] = pem
    sources_file.write_text(json.dumps(sources, indent=2) + '\n')
    joined = args.cache / 'joined-all.csv'
    with joined.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=['CA Owner', 'SHA-256 Fingerprint', 'PEM Info'])
        writer.writeheader()
        for row in rows:
            fp = row['SHA-256 Fingerprint'].replace(':', '').lower()
            writer.writerow({'CA Owner': row['CA Owner'], 'SHA-256 Fingerprint': fp, 'PEM Info': pems.get(fp, '')})
    raw_path = args.output.with_name(args.output.stem + '-full.json')
    command = [str(args.binary.resolve()), 'check', '--small-max', str(args.small_max),
               '--ccadb', str(joined), '--output', str(raw_path)]
    for directory in args.pack_dir:
        command += ['--pack-dir', str(directory)]
    completed = subprocess.run(command)
    if completed.returncode not in [0, 1] or not raw_path.exists():
        raise RuntimeError(f'Checker failed with exit status {completed.returncode}')
    report = json.loads(raw_path.read_text())
    if report['input_certificates'] + len(report['input_errors']) != len(rows):
        raise ValueError('Inventory accounting mismatch')
    now = datetime.now(timezone.utc)
    selected = []
    for cert in report['ec_certificates']:
        row = rows[int(cert['source'].rsplit(':row:', 1)[1]) - 2]
        assert row['SHA-256 Fingerprint'].replace(':', '').lower() == cert['certificate_sha256']
        if (cert['is_ca'] and cert['not_before_unix'] <= now.timestamp() <= cert['not_after_unix']
                and row['Revocation Status'] in ['', 'Not Revoked']):
            selected.append({**cert, 'record_type': row['Certificate Record Type'],
                             'reported_revocation_status': row['Revocation Status'],
                             'root_store_status': row['Status of Root Cert'],
                             'has_included_root_metadata': any(v.strip().endswith(': Included') for v in row['Status of Root Cert'].split(';'))})
    current_fps = {c['certificate_sha256'] for c in selected}
    current_findings = []
    for finding in report['findings']:
        certs = [c for c in finding['certificates'] if c['certificate_sha256'] in current_fps]
        if certs:
            current_findings.append({**finding, 'certificates': certs})
    summary = {
        'as_of_utc': now.isoformat(), 'sources': sources, 'inventory_rows': len(rows),
        'parsed_certificates': report['input_certificates'], 'input_errors': report['input_errors'],
        'all_supported_ec_certificates': report['supported_ec_certificates'],
        'all_distinct_ec_keys': report['distinct_ec_keys'], 'pack_count': report['pack_count'],
        'small_scalar_max_inclusive': report['small_scalar_max_inclusive'],
        'current_supported_ec_certificates': len(selected),
        'current_unique_ec_certificates': len({c['certificate_sha256'] for c in selected}),
        'current_distinct_ec_keys': len({c['normalized_point_sha256'] for c in selected}),
        'current_ec_with_included_root_metadata': sum(c['has_included_root_metadata'] for c in selected),
        'current_ec_revocation_status_unreported': sum(c['reported_revocation_status'] == '' for c in selected),
        'current_findings': current_findings, 'all_inventory_distinct_weak_keys': len(report['findings']),
        'rejected_tag_collisions': report['rejected_tag_collisions'],
        'current_certificates': selected, 'full_report': str(raw_path),
        'limitations': report['limitations'] + [
            'Current means time-valid CA certificates with no explicit CCADB revocation; blank root revocation fields are counted and disclosed.',
            'Included-root metadata does not establish a verified usable trust chain.',
            'This covers this CCADB snapshot, not every private CA or undisclosed certificate worldwide.',
        ],
    }
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ['sources', 'current_certificates', 'limitations', 'input_errors', 'current_findings']}, indent=2))
    print(f"Current weak-key findings: {len(current_findings)}; input errors: {len(report['input_errors'])}; report: {args.output}")
    raise SystemExit(completed.returncode)


if __name__ == '__main__':
    main()
