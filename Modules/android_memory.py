"""Bounded Frida memory sampling with Android-aware YARA and address evidence."""
import hashlib
from pathlib import Path
import time

from dynamic_memory import extract_iocs
from analysis.multiple.android_yara import AndroidRules, compile_rule_file, _compact_rules


class AndroidMemoryScanner:
    WINDOW = 256 * 1024
    OVERLAP = 4096

    def __init__(self, rule_paths, output_dir, *, metadata=None, export=True):
        self.paths = [Path(path) for path in rule_paths]
        self.output_dir = Path(output_dir)
        self.metadata = metadata or {}
        self.export = export
        self.rules = []
        self.cursors = {}
        self.exported = set()
        self.export_bytes = 0
        self.report = {'status': 'starting', 'rule_files': 0, 'errors': [],
                       'metadata_unavailable': [], 'samples': [], 'matches': [],
                       'iocs': [], 'exports': [], 'bytes_read': 0, 'truncated': {},
                       'scope': 'Readable process-memory windows; sampled coverage, not a full-file scan.',
                       'malware_verdict': None}
        self._seen = set()

    def prepare(self):
        files = []
        for path in self.paths:
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                files.extend(sorted(p for p in path.rglob('*') if p.suffix.lower() in ('.yar', '.yara')))
            else:
                self.report['errors'].append({'source': str(path), 'error': 'Rule path does not exist'})
        for path in dict.fromkeys(files):
            try:
                rules = compile_rule_file(path)
                if isinstance(rules, AndroidRules):
                    unavailable = sorted(rules.fields - self.metadata.keys())
                    if unavailable:
                        self.report['metadata_unavailable'].append({'source': str(path), 'fields': unavailable})
                else:
                    rules = _compact_rules(rules)
                self.rules.append((str(path), rules))
            except Exception as error:
                self.report['errors'].append({'source': str(path), 'error': str(error)})
        self.report['rule_files'] = len(self.rules)
        self.report['status'] = 'ready' if self.rules else 'ioc_only'

    def _append(self, key, item, identity):
        fingerprint = (key, identity, item.get('source'), item.get('rule'), item.get('kind'),
                       item.get('value'), item.get('address'))
        if fingerprint in self._seen:
            return
        if len(self.report[key]) >= 1000:
            self.report['truncated'][key] = self.report['truncated'].get(key, 0) + 1
            return
        self._seen.add(fingerprint)
        self.report[key].append(dict(item, process_identity=identity))

    def scan(self, identity, rpc, stop, *, max_bytes=2 * 1024 * 1024, seconds=3):
        started = time.monotonic()
        result = {'process_identity': identity, 'status': 'sampled', 'bytes_read': 0,
                  'windows': 0, 'rule_evaluations': 0, 'rule_timeouts': 0,
                  'errors': [], 'started_at': time.time()}
        self.report['status'] = 'running'
        try:
            enumeration = rpc('ranges')
            regions = sorted(enumeration['ranges'], key=lambda row: int(row['base'], 16))
            result['range_list_truncated'] = enumeration.get('truncated', False)
            result['enumerated_bytes'] = sum(row['size'] for row in regions)
            cursor = self.cursors.get(identity, 0)
            if not any(int(row['base'], 16) + row['size'] > cursor for row in regions):
                cursor = 0
            tail = b''
            for region in regions:
                base = int(region['base'], 16)
                end = base + int(region['size'])
                if end <= cursor:
                    continue
                position = max(base, cursor)
                tail = b''
                while position < end:
                    if stop.is_set() or result['bytes_read'] >= max_bytes or time.monotonic() - started >= seconds:
                        return result
                    size = min(self.WINDOW, end - position, max_bytes - result['bytes_read'])
                    try:
                        data = rpc('read_bytes', hex(position), size)
                        if not isinstance(data, bytes) or not data or len(data) > size:
                            raise ValueError('Invalid memory response')
                    except Exception as error:
                        if len(result['errors']) < 8:
                            result['errors'].append({'address': position, 'error': str(error)})
                        position += size
                        self.cursors[identity] = position
                        tail = b''
                        continue
                    block, address = tail + data, position - len(tail)
                    result['bytes_read'] += len(data)
                    result['windows'] += 1
                    for item in extract_iocs(block, address, limit=128):
                        self._append('iocs', dict(item, pid=int(identity.split(':')[0])), identity)
                    matched = False
                    for source, rules in self.rules:
                        if stop.is_set() or time.monotonic() - started >= seconds:
                            result['rule_budget_reached'] = True
                            break
                        try:
                            kwargs = {'metadata': self.metadata} if isinstance(rules, AndroidRules) else {}
                            matches = rules.match(data=block, timeout=1, **kwargs)
                            result['rule_evaluations'] += 1
                            for match in matches:
                                strings = []
                                for string in match.strings:
                                    for instance in string.instances:
                                        if len(strings) < 24:
                                            strings.append({'identifier': string.identifier,
                                                'address': address + instance.offset, 'length': instance.matched_length})
                                item = {'pid': int(identity.split(':')[0]), 'rule': match.rule,
                                        'source': source, 'address': address, 'window_size': len(block),
                                        'region': dict(region), 'strings': strings, 'classification': 'candidate',
                                        'basis': 'memory_window'}
                                self._append('matches', item, identity)
                                matched = True
                        except Exception as error:
                            if 'timeout' in str(type(error)).lower():
                                result['rule_timeouts'] += 1
                            if len(result['errors']) < 8:
                                result['errors'].append({'source': source, 'error': str(error)})
                    if self.export and matched and self.export_bytes + len(block) <= 16 * 1024 * 1024:
                        digest = hashlib.sha256(block).hexdigest()
                        key = (identity, address, digest)
                        if key not in self.exported:
                            folder = self.output_dir / 'memory_regions'
                            folder.mkdir(exist_ok=True)
                            path = folder / f'{identity.replace(":", "-")}_{address:x}_{digest[:16]}.bin'
                            path.write_bytes(block)
                            self.exported.add(key)
                            self.export_bytes += len(block)
                            self.report['exports'].append({'path': str(path), 'process_identity': identity,
                                'address': address, 'bytes': len(block), 'sha256': digest,
                                'complete_region': address == base and len(block) == region['size']})
                    position += len(data)
                    self.cursors[identity] = position
                    tail = block[-self.OVERLAP:]
                cursor = 0
            self.cursors[identity] = 0
            result['reached_last_enumerated_range'] = True
            return result
        except Exception as error:
            result['status'] = 'error'
            result['errors'].append({'error': str(error)})
            return result
        finally:
            result['duration_seconds'] = round(time.monotonic() - started, 3)
            self.report['bytes_read'] += result['bytes_read']
            self.report['samples'].append(result)
            if len(self.report['samples']) > 100:
                self.report['samples'].pop(0)
                self.report['truncated']['samples'] = self.report['truncated'].get('samples', 0) + 1
