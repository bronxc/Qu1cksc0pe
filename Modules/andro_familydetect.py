#!/usr/bin/env python3
"""Evidence-based Android family candidates from the current APK workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re


class AndroidFamilyDetect:
    MAX_FILE_BYTES = 4 * 1024 * 1024
    MAX_TOTAL_BYTES = 64 * 1024 * 1024
    MAX_FILES = 10000
    GENERIC_INDICATORS = {
        'overlayservice', 'myadminreceiver', 'accessibilityactivity', 'adminactivity',
        'headlesssmssendservice', 'appaccessibilityservice', 'workerservice',
        'encryptorservice', 'smsreceiver', 'mmsreceiver', 'xiaomiloadactivity', 'nointernet',
    }

    def __init__(self, target_apk, *, source_dir=None, apk=None, patterns=None):
        self.target = str(target_apk)
        self.source_dir = Path(source_dir).resolve() if source_dir else None
        self.apk = apk
        self.patterns = patterns if patterns is not None else json.loads(
            (Path(__file__).resolve().parents[1] / 'Systems/Android/family.json').read_text())
        self.report = {'status': 'ok', 'candidates': [], 'observations': [], 'errors': [],
                       'source_coverage': {'files': 0, 'bytes': 0, 'skipped': 0},
                       'malware_verdict': None,
                       'method': 'At least two distinct indicators including a non-generic indicator. Class-name dot/case variants count once; generic components alone do not identify a family.'}
        self.evidence = {name: {} for name in self.patterns}

    def _record(self, family, pattern, kind, location):
        key = pattern.casefold()
        if re.fullmatch(r'\.?[A-Za-z_$][\w$]*', pattern):
            key = key.lstrip('.')
        bucket = self.evidence.setdefault(family, {})
        item = bucket.setdefault(key, {'indicator': pattern, 'kinds': [], 'locations': [],
                                       'generic': key in self.GENERIC_INDICATORS})
        if kind not in item['kinds']:
            item['kinds'].append(kind)
        if location not in item['locations'] and len(item['locations']) < 5:
            item['locations'].append(location)

    def _manifest(self):
        if self.apk is None:
            try:
                from android_archive import validate_apk_size
                validate_apk_size(self.target)
                from androguard.core.bytecodes.apk import APK
                self.apk = APK(self.target)
            except Exception as error:
                self.report['errors'].append('APK parsing: ' + str(error))
                return
        all_names = []
        for category, getter in [('Activities', 'get_activities'), ('Services', 'get_services'),
                                 ('Receivers', 'get_receivers'), ('Providers', 'get_providers')]:
            try:
                names = getattr(self.apk, getter)() or []
            except Exception as error:
                self.report['errors'].append(category + ': ' + str(error))
                continue
            all_names.extend(names)
            for family, values in self.patterns.items():
                for pattern in values.get(category, []):
                    for name in names:
                        # The catalog contains class names, not regular expressions.
                        if name == pattern or name.endswith('.' + pattern.lstrip('.')):
                            self._record(family, pattern, 'manifest', name)
        obfuscated = [name for name in all_names if re.search(r'\.p[a-z0-9]{8}$', name)]
        if len(obfuscated) >= 3:
            self.report['observations'].append({'type': 'obfuscated_component_names', 'count': len(obfuscated),
                'detail': 'Naming alone does not identify FluBot or prove malicious behavior.'})

    def _sources(self):
        coverage = self.report['source_coverage']
        if self.source_dir is None or not self.source_dir.is_dir():
            coverage['status'] = 'unavailable'
            return
        coverage['status'] = 'ok'
        patterns = {family: list(dict.fromkeys(data.get('SourcePatterns', []))) for family, data in self.patterns.items()}
        # Common text such as root@, App Helper or SCDir is not family evidence.
        spy = ['/Config/sys/apps/tch', '/Config/sys/apps/rc', '/exit/chat/', 'spymax.stub']
        patterns.setdefault('SpyNote/SpyMax', []).extend(spy)
        weak = {'root@', 'app helper', 'scdir'}
        for subtree in ('sources', 'resources'):
            base = self.source_dir / subtree
            if base.is_symlink():
                coverage['skipped'] += 1
                continue
            for directory, dirs, files in os.walk(base, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
                for filename in sorted(files):
                    path = Path(directory) / filename
                    if coverage['files'] >= self.MAX_FILES or coverage['bytes'] >= self.MAX_TOTAL_BYTES:
                        coverage['status'] = 'partial'
                        coverage['limit_reached'] = True
                        return
                    try:
                        if path.is_symlink() or not path.is_file() or path.stat().st_size > self.MAX_FILE_BYTES:
                            coverage['skipped'] += 1
                            continue
                        remaining = min(self.MAX_FILE_BYTES, self.MAX_TOTAL_BYTES - coverage['bytes'])
                        with path.open('rb') as source:
                            data = source.read(remaining + 1)
                        if len(data) > remaining:
                            coverage['skipped'] += 1
                            continue
                        coverage['files'] += 1
                        coverage['bytes'] += len(data)
                        text = data.decode('utf-8', 'replace')
                        relative = path.relative_to(self.source_dir).as_posix()
                        for family, values in patterns.items():
                            for pattern in values:
                                if pattern.casefold() not in weak and pattern in text:
                                    self._record(family, pattern, 'source', relative)
                        if filename in ('SensorRestarterBroadcastReceiver.java', '_ask_remove_.java', 'SimpleIME.java'):
                            self._record('SpyNote/SpyMax', path.stem, 'filename', relative)
                        sova = {'nointernet.html': '9d647b7f81404d0744ebd1ead58bf8a6f3b6beb0a98583a907a00b38ff9843c2',
                                'unique.html': '1b5f986ddee68791fffe37baa4c551feae8016a1b3964ede7e49ec697c3ce26b'}
                        if filename in sova and hashlib.sha256(data).hexdigest() == sova[filename]:
                            self._record('Sova', 'sha256:' + sova[filename], 'resource_hash', relative)
                    except OSError as error:
                        coverage['skipped'] += 1
                        if len(self.report['errors']) < 100:
                            self.report['errors'].append(str(error))
        if coverage['skipped']:
            coverage['status'] = 'partial'

    def CheckFamily(self, *, quiet=False):
        self._manifest()
        self._sources()
        for family, indicators in self.evidence.items():
            specific = any(not item['generic'] for item in indicators.values())
            if len(indicators) >= 2 and specific:
                self.report['candidates'].append({'family': family, 'distinct_indicators': len(indicators),
                    'confidence': 'candidate', 'evidence': list(indicators.values())})
            elif indicators:
                self.report['observations'].append({'family': family,
                                                    'type': 'insufficient_family_evidence' if specific else 'generic_component_names',
                                                    'evidence': list(indicators.values())})
        self.report['candidates'].sort(key=lambda item: (-item['distinct_indicators'], item['family']))
        if self.report['errors'] or self.report['source_coverage'].get('status') != 'ok':
            self.report['status'] = 'partial'
        if not quiet:
            from rich.console import Console
            console = Console()
            for candidate in self.report['candidates']:
                console.print(f"Family candidate: {candidate['family']} ({candidate['distinct_indicators']} distinct indicators)", markup=False)
            if not self.report['candidates']:
                console.print('No corroborated family candidate in the analyzed content.')
            if self.report['status'] == 'partial':
                console.print('Family analysis coverage is partial; see report details.')
        return self.report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk')
    parser.add_argument('--source-dir', help='Decompiler output belonging to this APK')
    parser.add_argument('--json', metavar='PATH')
    args = parser.parse_args()
    result = AndroidFamilyDetect(args.apk, source_dir=args.source_dir).CheckFamily()
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding='utf-8')
