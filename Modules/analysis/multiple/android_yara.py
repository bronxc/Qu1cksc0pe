"""Evaluate the bundled Koodous predicates with ordinary yara-python.

Only module calls are adapted; YARA still evaluates strings, regexes and the
original condition. Missing metadata stays undefined, including under `not`.
String comparisons follow Koodous' case-insensitive exact comparisons:
https://github.com/Anlyz/androguard-yara/blob/master/androguard.c
"""
import ast
from collections import defaultdict
import hashlib
from pathlib import Path
import re
import time

import yara


_FIELDS = {
    "androguard." + name for name in (
        "package_name", "app_name", "activity", "receiver", "permission",
        "service", "filter", "url", "certificate.sha1",
    )
} | {"file.md5", "cuckoo.network.dns_lookup", "cuckoo.network.http_request",
     "droidbox.phonecall", "droidbox.written.data"}
_LEX = re.compile(
    r'(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<string>"(?:\\.|[^"\\])*")'
    r'|(?P<regex>/(?:\\.|[^/\\\n])+/[is]*)'
    r'|(?P<word>[A-Za-z_]\w*)|(?P<other>.)'
)
_MAX_VALUES = 4096
_MAX_VALUE_BYTES = 16384


def _tokens(source):
    return [m for m in _LEX.finditer(source) if m.lastgroup not in ("space", "comment")]


def _translate(source):
    tokens = _tokens(source)
    imports = {tokens[i + 1].group()[1:-1] for i, t in enumerate(tokens[:-1])
               if t.group() == "import" and tokens[i + 1].lastgroup == "string"}
    if "androguard" not in imports:
        return source, {}
    prefix = "sc0pe_meta_" + hashlib.sha256(source.encode()).hexdigest()[:16] + "_"
    if any(t.group().startswith(prefix) for t in tokens):
        raise ValueError("Reserved Android metadata identifier")
    replacements, predicates = [], {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.group() == "import" and i + 1 < len(tokens):
            if tokens[i + 1].group() in ('"androguard"', '"file"', '"cuckoo"', '"droidbox"'):
                replacements.append((token.start(), tokens[i + 1].end(), ""))
                i += 2
                continue
        if token.lastgroup != "word" or token.group() not in ("androguard", "file", "cuckoo", "droidbox"):
            i += 1
            continue
        j, field = i + 1, token.group()
        while j + 1 < len(tokens) and tokens[j].group() == ".":
            field += "." + tokens[j + 1].group()
            j += 2
        if j == i + 1:
            i += 1
            continue
        if (field not in _FIELDS or j + 2 >= len(tokens)
                or tokens[j].group() != "(" or tokens[j + 2].group() != ")"
                or tokens[j + 1].lastgroup not in ("string", "regex")):
            raise ValueError(f"Unsupported Koodous predicate: {field}")
        argument = tokens[j + 1].group()
        if field in ("androguard.certificate.sha1", "file.md5"):
            if tokens[j + 1].lastgroup != "string":
                raise ValueError(f"{field} requires a complete hash string")
            # Koodous accepts colon-separated, case-insensitive certificate hashes.
            normalized = ast.literal_eval(argument).replace(":", "")
            argument = '"' + normalized.replace("\\", "\\\\").replace('"', '\\"') + '"'
        key = (field, argument)
        if key not in predicates:
            predicates[key] = prefix + str(len(predicates))
        external = predicates[key]
        # Integer division by zero gives YARA's undefined value. Keep this an
        # arithmetic expression: boolean `or` can collapse undefined to false.
        # -1 -> undefined; 0 -> 0; 1 -> 1, including beneath `not`/`defined`.
        expression = f"(2 * {external} \\ ({external} + 1))"
        replacements.append((token.start(), tokens[j + 2].end(), expression))
        i = j + 3
    for start, end, replacement in reversed(replacements):
        # Retain line numbers for compiler diagnostics.
        source = source[:start] + replacement + "\n" * source[start:end].count("\n") + source[end:]
    return source, predicates


def _compact_rules(rules):
    """Release YARA compiler arena slack before retaining a metadata rule set.

    Tiny metadata probes otherwise retain several MiB each. Reloading the native
    serialization preserves matching semantics while allocating the used arena.
    """
    import io
    buffer = io.BytesIO()
    rules.save(file=buffer)
    buffer.seek(0)
    return yara.load(file=buffer)


class AndroidRules:
    def __init__(self, source, predicates):
        self.fields = frozenset(field for field, _ in predicates)
        self._predicates = predicates
        self._defaults = {name: -1 for name in predicates.values()}
        # Compile with a nonzero divisor; each match explicitly supplies the
        # actual values (including -1 for unavailable metadata).
        self._rules = yara.compile(source=source, externals={name: 0 for name in self._defaults})
        self._warnings = self._rules.warnings
        self._rules = _compact_rules(self._rules)
        grouped = defaultdict(list)
        for (field, argument), name in predicates.items():
            operator = "matches" if argument.startswith("/") else "iequals"
            grouped[field].append(f"rule {name} {{ condition: sc0pe_value {operator} {argument} }}")
        self._probes = {field: _compact_rules(yara.compile(source="\n".join(rules), externals={"sc0pe_value": ""}))
                        for field, rules in grouped.items()}

    def __iter__(self):
        return iter(self._rules)

    @property
    def warnings(self):
        return self._warnings

    def match(self, *args, metadata=None, timeout=2, **kwargs):
        deadline = time.monotonic() + timeout
        values = dict(self._defaults)
        metadata = metadata or {}
        for field, probe in self._probes.items():
            if field not in metadata:
                continue
            entries = metadata[field]
            if not isinstance(entries, (tuple, list)) or len(entries) > _MAX_VALUES:
                raise ValueError(f"Invalid or oversized Android metadata: {field}")
            for (predicate_field, _), name in self._predicates.items():
                if predicate_field == field:
                    values[name] = 0
            for entry in entries:
                if not isinstance(entry, str) or len(entry.encode("utf-8")) > _MAX_VALUE_BYTES:
                    raise ValueError(f"Invalid or oversized Android metadata value: {field}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise yara.TimeoutError("Android metadata match timed out")
                for match in probe.match(data=b"", externals={"sc0pe_value": entry},
                                         timeout=max(1, int(remaining))):
                    values[match.rule] = 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise yara.TimeoutError("Android metadata match timed out")
        return self._rules.match(*args, externals=values, timeout=max(1, int(remaining)), **kwargs)


def compile_rule_file(path):
    """Keep normal YARA files native; adapt only files importing androguard."""
    source = Path(path).read_text(encoding="utf-8-sig")
    translated, predicates = _translate(source)
    if translated == source:
        return yara.compile(filepath=str(path))
    return AndroidRules(translated, predicates)


def apk_metadata(apk):
    """Collect parsed manifest/signers; errors leave the affected field unknown.

    URLs come from parsed DEX strings. Sandbox predicates require a separate
    observation report and remain unknown; static URLs are not network activity.
    """
    metadata, errors = {}, []
    if apk is None:
        return metadata, ["APK metadata unavailable"]
    valid_manifest = apk.is_valid_APK()
    if not valid_manifest:
        errors.append("Full APK manifest unavailable; manifest predicates remain unknown")
        try:
            from android_apk_info import apk_info
            recovered = apk_info(apk.filename, apk)
            if recovered.get('package'):
                metadata['androguard.package_name'] = [recovered['package']]
        except Exception as exc:
            errors.append(f'APK identity recovery: {exc}')
    for field, method, scalar in (
        ("package_name", "get_package", True), ("app_name", "get_app_name", True),
        ("permission", "get_permissions", False), ("activity", "get_activities", False),
        ("receiver", "get_receivers", False), ("service", "get_services", False),
    ):
        if not valid_manifest:
            continue
        try:
            value = getattr(apk, method)()
            if value is None or (scalar and not value):
                raise ValueError("No parsed value")
            metadata["androguard." + field] = [value] if scalar else list(value)
        except Exception as exc:
            errors.append(f"{field}: {exc}")
    try:
        # Parse errors must not masquerade as an unsigned APK.
        certificates = apk.get_certificates()
        if not certificates:
            raise ValueError("No signing certificates extracted")
        metadata["androguard.certificate.sha1"] = [hashlib.sha1(c.dump()).hexdigest() for c in certificates]
    except Exception as exc:
        errors.append(f"certificate.sha1: {exc}")
    try:
        if not valid_manifest:
            raise ValueError('Full manifest unavailable')
        filters = set()
        for kind, field in (("activity", "activity"), ("receiver", "receiver"), ("service", "service")):
            for component in metadata["androguard." + field]:
                intents = apk.get_intent_filters(kind, component)
                for key in ("action", "category"):
                    filters.update(intents.get(key, []))
        metadata["androguard.filter"] = sorted(filters)
    except Exception as exc:
        errors.append(f"filter: {exc}")
    try:
        digest = hashlib.md5()
        with open(apk.filename, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        metadata["file.md5"] = [digest.hexdigest()]
    except Exception as exc:
        errors.append(f"file.md5: {exc}")
    try:
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        names = list(apk.get_dex_names())
        if len(names) > 32 or sum(apk.zip.getinfo(n).file_size for n in names) > 64 * 1024 * 1024:
            raise ValueError("DEX metadata extraction size limit exceeded")
        urls = set()
        pattern = re.compile(r'''(?:https?|ftp)://[^\s<>"'\x00]+''', re.IGNORECASE)
        for name in names:
            dex = DalvikVMFormat(apk.get_file(name))
            for value in dex.get_strings():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                for url in pattern.findall(value):
                    if len(url.encode("utf-8")) > _MAX_VALUE_BYTES:
                        raise ValueError("URL metadata extraction size limit exceeded")
                    urls.add(url)
                    if len(urls) > _MAX_VALUES:
                        raise ValueError("URL metadata extraction size limit exceeded")
        metadata["androguard.url"] = sorted(urls)
    except Exception as exc:
        errors.append(f"url: {exc}")
    return metadata, errors
