"""Recover limited APK identity without treating a partial manifest as complete."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile


def apk_info(filename, parsed=None):
    filename = str(Path(filename).resolve())
    result = {'source': 'androguard', 'status': 'partial', 'warnings': [], 'native_abis': []}
    with zipfile.ZipFile(filename) as archive:
        result['native_abis'] = sorted({name.split('/')[1] for name in archive.namelist()
            if name.startswith('lib/') and name.endswith('.so') and len(name.split('/')) >= 3})
    if parsed is None:
        from androguard.core.bytecodes.apk import APK
        try:
            parsed = APK(filename)
        except Exception as error:
            result['warnings'].append('Androguard: ' + str(error)[:500])
    if parsed is not None and parsed.is_valid_APK() and parsed.get_package():
        result.update(status='complete', package=parsed.get_package(),
            min_sdk=parsed.get_min_sdk_version(), target_sdk=parsed.get_target_sdk_version(),
            main_activity=parsed.get_main_activity(), permissions=parsed.get_permissions())
        return result
    aapt = shutil.which('aapt')
    if not aapt:
        result['warnings'].append('Manifest unreadable; install aapt to recover limited APK identity')
        return result
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.run([aapt, 'dump', 'badging', filename], stdout=stdout,
                                 stderr=stderr, timeout=20)
        if stdout.tell() > 2 * 1024 * 1024:
            raise ValueError('aapt badging output exceeds 2 MiB')
        stdout.seek(0); stderr.seek(0)
        output = stdout.read().decode('utf-8', 'replace')
        warning = stderr.read(2000).decode('utf-8', 'replace').strip()
    if process.returncode:
        result['warnings'].append('aapt failed: ' + warning)
        return result
    package = re.search(r"^package: name='([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)'", output, re.M | re.ASCII)
    if not package:
        result['warnings'].append('aapt did not recover a package identifier')
        return result
    result.update(source='aapt_badging', package=package[1],
                  permissions=sorted(set(re.findall(r"^uses-permission(?:-sdk-\d+)?: name='([^']+)'", output, re.M))))
    for field, pattern in (('min_sdk', r"^sdkVersion:'([^']+)'"),
                           ('target_sdk', r"^targetSdkVersion:'([^']+)'"),
                           ('main_activity', r"^launchable-activity: name='([^']+)'")):
        match = re.search(pattern, output, re.M)
        if match:
            result[field] = match[1]
    result['warnings'].append('Only APK identity and observed requested permissions recovered; full manifest unavailable')
    if warning:
        result['warnings'].append(warning)
    return result
