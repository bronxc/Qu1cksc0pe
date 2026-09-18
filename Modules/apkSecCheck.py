#!/usr/bin/env python3
"""Standalone and reusable Android manifest security report."""
import argparse
import json
from pathlib import Path
from android_manifest import analyze_manifest, analyze_apk_manifest
from android_archive import validate_apk_size


def print_security_report(report):
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    console = Console()
    console.print(f"Android manifest security: {report['status']}", markup=False)
    table = Table('Level', 'Finding', 'Component / scope')
    for item in report['findings']:
        table.add_row(Text(item['severity']), Text(item['code']), Text(item['subject'] or 'application'))
    console.print(table)
    for warning in report['warnings']:
        console.print(warning, markup=False)
    console.print('Configuration observations require context; they are not malware verdicts.')


def ManifestAnalysis(target, *, quiet=False):
    path = Path(target)
    if path.suffix.lower() == '.xml':
        with path.open('rb') as source:
            result = analyze_manifest(source.read(4 * 1024 * 1024 + 1))
    else:
        validate_apk_size(path)
        from androguard.core.bytecodes.apk import APK
        result = analyze_apk_manifest(APK(str(path)))
    if not quiet:
        print_security_report(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', help='APK or decoded AndroidManifest.xml')
    parser.add_argument('--json', metavar='PATH', help='Write structured findings')
    args = parser.parse_args()
    try:
        result = ManifestAnalysis(args.target)
    except Exception as error:
        parser.exit(1, f'Manifest analysis failed: {error}\n')
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 1 if result['status'] == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())
