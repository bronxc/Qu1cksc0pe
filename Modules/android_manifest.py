"""APK manifest observations with explicit defaults and unresolved-value coverage.

These are configuration findings, not malware verdicts. Device-specific behavior
is retained as context rather than guessed from the APK's target SDK.
"""
import re
import xml.etree.ElementTree as ET

ANDROID = '{http://schemas.android.com/apk/res/android}'
MAX_XML = 4 * 1024 * 1024
MAX_NODES = 20000


def xml_root(data):
    if hasattr(data, 'getroot'):
        data = data.getroot()
    if hasattr(data, 'tag'):
        root = data
    else:
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not isinstance(data, bytes) or len(data) > MAX_XML:
            raise ValueError('XML is missing or exceeds 4 MiB')
        # Do not accept DTD/entity declarations, including UTF-16/32 encodings.
        if re.search(br'<!\s*(?:DOCTYPE|ENTITY)', data.replace(b'\0', b''), re.I):
            raise ValueError('XML DTD/entity declarations are not supported')
        root = ET.fromstring(data)
    if root is None or sum(1 for _ in root.iter()) > MAX_NODES:
        raise ValueError('XML is missing or exceeds the node limit')
    return root


def boolean(value, default=None):
    if value is None:
        return {'value': default, 'origin': 'default', 'raw': None}
    lowered = str(value).strip().lower()
    parsed = {'true': True, 'false': False, '1': True, '0': False,
              '0xffffffff': True}.get(lowered)
    return {'value': parsed, 'origin': 'explicit' if parsed is not None else 'unresolved',
            'raw': value}


def _sdk(raw, default):
    try:
        value = int(raw) if raw is not None else default
        return value if value is not None and value >= 1 else None
    except (TypeError, ValueError):
        return None


def permission_level(raw):
    raw = 'normal' if raw is None else str(raw)
    names = {0: 'normal', 1: 'dangerous', 2: 'signature', 3: 'signatureOrSystem',
             4: 'internal'}
    try:
        base = names.get(int(raw, 16 if raw.startswith('0x') else 10) & 15, 'unknown')
    except ValueError:
        base = raw.split('|', 1)[0].strip()
        if base not in names.values():
            base = 'unknown'
    return {'raw': raw, 'base': base}


def network_config(data, target_sdk, debuggable=False):
    root = xml_root(data)
    if root.tag != 'network-security-config':
        raise ValueError('Expected network-security-config root')
    defaults = {'cleartext': None if target_sdk is None else target_sdk < 28,
                'trust_anchors': None if target_sdk is None else
                    (['system', 'user'] if target_sdk < 24 else ['system'])}
    result = {'status': 'ok', 'applies_on': 'Android API 24+', 'policies': [],
              'debug_overrides': [], 'warnings': [],
              'notes': ['API 37+ adds implicit localhost exceptions when no localhost policy exists.',
                        'Policy does not prove traffic occurred or govern every native socket.']}

    def visit(node, inherited, scope, depth=0):
        if depth > 64:
            raise ValueError('Network configuration nesting exceeds 64')
        raw = node.get('cleartextTrafficPermitted') if node is not None else None
        cleartext = boolean(raw, inherited['cleartext'])
        anchors = node.find('trust-anchors') if node is not None else None
        trust = ([x.get('src') for x in anchors.findall('certificates')]
                 if anchors is not None else inherited['trust_anchors'])
        policy = {'scope': scope, 'cleartext': cleartext['value'],
                  'cleartext_origin': 'inherited' if raw is None else cleartext['origin'],
                  'trust_anchors': trust}
        if node is not None:
            policy['domains'] = [{'name': (x.text or '').strip(),
                                  'include_subdomains': boolean(x.get('includeSubdomains'), False)['value']}
                                 for x in node.findall('domain')]
            pins = node.find('pin-set')
            if pins is not None:
                policy['pin_set'] = {'expiration': pins.get('expiration'),
                                     'count': len(pins.findall('pin'))}
        result['policies'].append(policy)
        if cleartext['origin'] == 'unresolved' or trust is None:
            result['status'] = 'partial'
        if node is not None:
            for index, child in enumerate(node.findall('domain-config')):
                visit(child, policy, f'{scope}/domain-config[{index}]', depth + 1)
        return policy

    base = visit(root.find('base-config'), defaults, 'base-config')
    for index, child in enumerate(root.findall('domain-config')):
        visit(child, base, f'domain-config[{index}]')
    for child in root.findall('debug-overrides'):
        result['debug_overrides'].append({'active': debuggable,
            'trust_anchors': [x.get('src') for x in child.findall('trust-anchors/certificates')]})
    return result


def analyze_manifest(data, network_configs=None):
    report = {'status': 'ok', 'package': None, 'sdk': {}, 'application': {},
              'permissions': [], 'components': [], 'findings': [], 'warnings': [],
              'network_security': {'status': 'not_declared'}, 'malware_verdict': None}

    def finding(code, severity, subject, detail, **evidence):
        report['findings'].append({'code': code, 'severity': severity, 'subject': subject,
                                   'detail': detail, 'evidence': evidence})

    try:
        root = xml_root(data)
        if root.tag != 'manifest':
            raise ValueError('Expected manifest root')
    except (ValueError, ET.ParseError, TypeError) as error:
        report.update(status='error', warnings=[str(error)])
        return report
    report['package'] = root.get('package')
    sdk = root.find('uses-sdk')
    minimum = _sdk(sdk.get(ANDROID + 'minSdkVersion') if sdk is not None else None, 1)
    target = _sdk(sdk.get(ANDROID + 'targetSdkVersion') if sdk is not None else None, minimum)
    report['sdk'] = {'min': minimum, 'target': target,
                     'target_origin': 'explicit' if sdk is not None and ANDROID + 'targetSdkVersion' in sdk.attrib else 'default_to_min'}
    if target is None:
        report['warnings'].append('Unresolved target SDK; SDK-dependent defaults remain unknown.')
    apps = root.findall('application')
    if len(apps) != 1:
        report.update(status='error')
        report['warnings'].append('Expected exactly one application element.')
        return report
    app = apps[0]
    flags = report['application']
    for name, default in [('debuggable', False), ('allowBackup', True), ('enabled', True),
                          ('testOnly', False), ('usesCleartextTraffic', None if target is None else target < 28)]:
        flags[name] = boolean(app.get(ANDROID + name), default)
    for name in ('networkSecurityConfig', 'fullBackupContent', 'dataExtractionRules', 'permission'):
        flags[name] = app.get(ANDROID + name)
    if flags['debuggable']['value'] is True:
        finding('debuggable', 'warning', 'application', 'Release builds should disable debugging.', **flags['debuggable'])
    if flags['allowBackup']['value'] is True:
        finding('backup_enabled', 'info', 'application',
                'Review backup exclusions for sensitive data; backup support alone is not a vulnerability.',
                fullBackupContent=flags['fullBackupContent'], dataExtractionRules=flags['dataExtractionRules'])
    flags['backup_context'] = 'API 31+ device-to-device migration can vary by manufacturer even with allowBackup=false.'
    ref = flags['networkSecurityConfig']
    if ref:
        variants = (network_configs or {}).get(ref)
        if not variants:
            report['network_security'] = {'status': 'unresolved', 'reference': ref}
            report['warnings'].append('Referenced network security XML is unresolved; cleartext policy is unknown on API 24+.')
        else:
            configs = []
            for name, xml in variants:
                try:
                    config = network_config(xml, target, flags['debuggable']['value'])
                    config['resource'] = name
                    configs.append(config)
                    for policy in config['policies']:
                        if policy['cleartext'] is True:
                            finding('cleartext_allowed', 'warning', name + ':' + policy['scope'],
                                    'Configuration permits cleartext for this scope on API 24+.', policy=policy)
                        if policy['trust_anchors'] and 'user' in policy['trust_anchors']:
                            finding('user_ca_trust', 'info', name + ':' + policy['scope'],
                                    'User-installed certificate authorities are trusted in this scope.', policy=policy)
                except (ValueError, ET.ParseError, TypeError) as error:
                    configs.append({'resource': name, 'status': 'error', 'error': str(error)})
            report['network_security'] = {'status': 'ok' if all(x['status'] == 'ok' for x in configs) else 'partial',
                                          'reference': ref, 'variants': configs}
        flags['usesCleartextTraffic']['context'] = 'Ignored on API 24+ when networkSecurityConfig is present; retained for older devices.'
    else:
        if flags['usesCleartextTraffic']['value'] is True:
            finding('cleartext_allowed', 'warning', 'application',
                    'Manifest policy permits cleartext where the platform honors this flag; this is not observed traffic.',
                    **flags['usesCleartextTraffic'])
        if target is not None and target >= 38:
            flags['usesCleartextTraffic']['context'] = 'Ignored for target SDK 38+; network security configuration controls policy.'
            report['findings'] = [x for x in report['findings'] if x['code'] != 'cleartext_allowed']

    defined = {}
    for perm in root.findall('permission'):
        name = perm.get(ANDROID + 'name')
        level = permission_level(perm.get(ANDROID + 'protectionLevel'))
        defined[name] = level['base']
        report['permissions'].append({'name': name, 'protection_level': level})
        if level['base'] in ('normal', 'dangerous'):
            finding('weak_custom_permission', 'info', name,
                    'Other apps may obtain this permission; review components relying on it.', **level)

    def qualified(name):
        if not name:
            return name
        package = report['package'] or ''
        return package + name if name.startswith('.') else (package + '.' + name if '.' not in name else name)

    for component in app:
        if component.tag not in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            continue
        kind, name = component.tag, qualified(component.get(ANDROID + 'name'))
        filters = component.findall('intent-filter')
        default = (None if target is None else target < 17) if kind == 'provider' else bool(filters)
        exported = boolean(component.get(ANDROID + 'exported'), default)
        enabled = boolean(component.get(ANDROID + 'enabled'), True)
        effective_enabled = (False if False in (enabled['value'], flags['enabled']['value']) else
                             True if enabled['value'] is True and flags['enabled']['value'] is True else None)
        permission = component.get(ANDROID + 'permission', '' if kind == 'activity-alias' else flags['permission'])
        actions = sorted({x.get(ANDROID + 'name') for f in filters for x in f.findall('action') if x.get(ANDROID + 'name')})
        launcher = any(any(x.get(ANDROID + 'name') == 'android.intent.action.MAIN' for x in f.findall('action'))
                       and any(x.get(ANDROID + 'name') == 'android.intent.category.LAUNCHER' for x in f.findall('category')) for f in filters)
        item = {'type': kind, 'name': name, 'exported': exported, 'enabled': effective_enabled,
                'permission': permission, 'permission_strength': defined.get(permission, 'external_unknown') if permission else 'none',
                'intent_actions': actions, 'launcher': launcher}
        if kind == 'activity-alias':
            item['target_activity'] = qualified(component.get(ANDROID + 'targetActivity'))
        if kind == 'provider':
            item.update(read_permission=component.get(ANDROID + 'readPermission', permission),
                        write_permission=component.get(ANDROID + 'writePermission', permission),
                        authorities=component.get(ANDROID + 'authorities'),
                        grant_uri_permissions=boolean(component.get(ANDROID + 'grantUriPermissions'), False),
                        path_permissions=[dict(x.attrib) for x in component.findall('path-permission')])
            item['context'] = 'On API 16 and below providers behave as exported; URI grants and path permissions may alter access.'
        elif filters and component.get(ANDROID + 'exported') is None and target is not None and target >= 31:
            item['installability'] = 'invalid_on_api_31_plus'
            finding('missing_exported', 'warning', name,
                    'Target SDK 31+ components with intent filters must declare exported to install on Android 12+.', type=kind)
        report['components'].append(item)
        unguarded = (not item.get('read_permission') or not item.get('write_permission')) if kind == 'provider' else not permission
        if exported['value'] is True and effective_enabled is True and unguarded and 'installability' not in item:
            finding('exported_without_permission', 'info' if launcher else 'review', name,
                    'Other applications may reach this component; inspect input validation and runtime permission checks.',
                    type=kind, launcher=launcher, exported=exported,
                    read_permission=item.get('read_permission'), write_permission=item.get('write_permission'))
    unresolved = any(v.get('origin') == 'unresolved' for v in flags.values() if isinstance(v, dict))
    unresolved |= any(x['exported']['value'] is None or x['enabled'] is None for x in report['components'])
    if unresolved or report['warnings'] or report['network_security']['status'] in ('unresolved', 'partial'):
        report['status'] = 'partial'
    return report


def analyze_apk_manifest(apk):
    """Resolve binary manifest/XML resources without depending on JADX output."""
    if apk is None:
        return analyze_manifest(None)
    try:
        root = apk.get_android_manifest_xml()
        result = analyze_manifest(root)
        if result['status'] == 'error':
            from android_apk_info import apk_info
            recovered = apk_info(apk.get_filename(), apk)
            result['identity_recovery'] = recovered
            if recovered.get('package'):
                result.update(status='partial', package=recovered['package'],
                    observed_requested_permissions=recovered.get('permissions', []))
                result['network_security'] = {'status': 'unresolved'}
                result['warnings'].extend(recovered['warnings'])
            return result
        reference = result['application'].get('networkSecurityConfig')
        if not reference:
            return result
        resources = apk.get_android_resources()
        paths = []
        if resources is not None:
            if re.fullmatch(r'@[0-9a-fA-F]{8}', reference):
                resource_id = int(reference[1:], 16)
            else:
                match = re.fullmatch(r'@(?:([^:]+):)?xml/(\w+)', reference)
                resource_id = resources.get_res_id_by_key(match.group(1) or apk.get_package(), 'xml', match.group(2)) if match else None
            if resource_id:
                paths = [value for _, value in resources.get_resolved_res_configs(resource_id)]
        if len(paths) > 64:
            raise ValueError('Network security resource variants exceed 64')
        configs = []
        for path in dict.fromkeys(paths):
            if not isinstance(path, str) or not path.startswith('res/'):
                continue
            from androguard.core.bytecodes.axml import AXMLPrinter
            # Read with a bound before passing binary XML to the parser.
            import zipfile
            with zipfile.ZipFile(apk.get_filename()) as archive:
                info = archive.getinfo(path)
                if info.file_size > MAX_XML:
                    raise ValueError('Network security XML exceeds 4 MiB')
                data = archive.read(info)
            xml = data if data.lstrip().startswith(b'<') else AXMLPrinter(data).get_xml_obj()
            configs.append((path, xml))
        return analyze_manifest(root, {reference: configs})
    except Exception as error:
        result = locals().get('result', analyze_manifest(None))
        result['status'] = 'partial' if result['application'] else 'error'
        result['warnings'].append('APK manifest/resource parsing failed: ' + str(error))
        return result
