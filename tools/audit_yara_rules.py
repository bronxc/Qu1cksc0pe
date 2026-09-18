"""Audit bundled rules. Run rule compilation in a lab VM.

Exit 1 for compilation failures or rules matching empty input.
Content hashes are informational; no provenance baseline is required.
Uses the application's Koodous adapter for Android metadata rules. Such files
are compiled individually; combined compilation covers native YARA files only.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import time
import sys


def canonical_sha256(data):
    return hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()


def audit(root):
    import yara
    root = Path(root).resolve()
    sys.path.insert(0, str(root / "Modules"))
    from analysis.multiple.android_yara import AndroidRules, compile_rule_file
    report = {'yara_version': yara.__version__, 'files': [], 'unexpected_errors': [],
              'combined_compilation': {}, 'platforms': {}, 'empty_input_matches': []}
    groups = defaultdict(dict)
    begin = time.monotonic()
    for path in sorted((root/'Systems').rglob('*')):
        if not path.is_file() or path.suffix.lower() not in ('.yar', '.yara'):
            continue
        rel = path.relative_to(root).as_posix()
        item = {'path': rel}
        try:
            item['sha256'] = canonical_sha256(path.read_bytes())
            compiled = compile_rule_file(path)
            item.update(status='compiled', rules=[r.identifier for r in compiled], warnings=compiled.warnings)
            if isinstance(compiled, AndroidRules):
                item['engine'] = 'koodous_metadata_adapter'
                item['required_metadata'] = sorted(compiled.fields)
            # A compile-only check misses conditions such as `2 or all of (...)`.
            # Check legacy files as well as newly imported ones.
            empty_matches = [m.rule for m in compiled.match(data=b'', timeout=1)]
            if empty_matches:
                finding = {'path': rel, 'error': 'Rules match empty input', 'rules': empty_matches}
                report['empty_input_matches'].append(finding)
                report['unexpected_errors'].append(finding)
            directory = path.parent.relative_to(root).as_posix()
            if not isinstance(compiled, AndroidRules):
                groups[directory][f'file_{len(groups[directory])}'] = str(path)
        except Exception as exc:
            item.update(status='error', error=str(exc))
            report['unexpected_errors'].append({'path': rel, 'error': str(exc)})
        report['files'].append(item)
    for directory, files in groups.items():
        try:
            rules = yara.compile(filepaths=files)
            report['combined_compilation'][directory] = {'files': len(files), 'rules': sum(1 for _ in rules),
                                                        'scope': 'native_yara_files'}
        except Exception as exc:
            report['unexpected_errors'].append({'path': directory, 'error': f'Combined compilation: {exc}'})
    for platform in sorted({f['path'].split('/')[1] for f in report['files']}):
        report['platforms'][platform] = dict(Counter(f['status'] for f in report['files'] if f['path'].split('/')[1] == platform))
    report['seconds'] = round(time.monotonic() - begin, 3)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, help='Write full JSON audit')
    options = parser.parse_args()
    result = audit(options.root)
    if options.output:
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'files'}, indent=2))
    raise SystemExit(bool(result['unexpected_errors']))
