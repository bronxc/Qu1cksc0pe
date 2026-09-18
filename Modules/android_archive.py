"""Bounded, non-overwriting extraction into an analysis-owned directory."""
from pathlib import Path, PurePosixPath
import stat
import tempfile
import zipfile


def validate_apk_size(filename):
    """Reject oversized containers before APK libraries eagerly expand members."""
    if Path(filename).stat().st_size > 256 * 1024 * 1024:
        raise ValueError('APK exceeds 256 MiB input limit')
    with zipfile.ZipFile(filename) as archive:
        infos = archive.infolist()
        if len(infos) > 20000 or sum(x.file_size for x in infos) > 512 * 1024 * 1024:
            raise ValueError('APK exceeds member count or 512 MiB expanded size limit')
        if any(x.file_size > 128 * 1024 * 1024 or
               x.file_size > max(x.compress_size, 1) * 1000 for x in infos):
            raise ValueError('APK exceeds member size or compression ratio limit')


class ArchiveBudget:
    def __init__(self, *, member_bytes=64 * 1024 * 1024,
                 total_bytes=256 * 1024 * 1024, members=2048, ratio=1000):
        self.member_bytes = member_bytes
        self.total_bytes = total_bytes
        self.members = members
        self.ratio = ratio
        self.used = 0
        self.count = 0
        self.skipped = 0
        self.errors = []

    def reject(self, name, reason):
        self.skipped += 1
        if len(self.errors) < 200:
            self.errors.append({'member': name, 'reason': str(reason)})
        return None

    def extract(self, archive, info, destination):
        name = info.filename
        parts = PurePosixPath(name).parts
        if (not parts or name.startswith(('/', '\\')) or '\\' in name or ':' in name
                or '..' in parts or '\0' in name or info.is_dir()):
            return self.reject(name, 'unsafe_member_path')
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)):
            return self.reject(name, 'non_regular_member')
        if info.flag_bits & 1:
            return self.reject(name, 'encrypted_member')
        if self.count >= self.members or self.used + info.file_size > self.total_bytes:
            return self.reject(name, 'aggregate_limit')
        if info.file_size > self.member_bytes or info.file_size > max(info.compress_size, 1) * self.ratio:
            return self.reject(name, 'member_size_or_compression_limit')
        destination = Path(destination)
        if any(p.is_symlink() for p in (destination, *destination.parents)):
            return self.reject(name, 'symlink_destination')
        root = destination.resolve()
        target = root.joinpath(*parts)
        if not target.resolve().is_relative_to(root):
            return self.reject(name, 'path_outside_destination')
        if any(p.is_symlink() for p in (target, *target.parents)):
            return self.reject(name, 'symlink_member_path')
        count = 0
        created = False
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open('xb') as output:
                created = True
                self.count += 1
                while True:
                    chunk = source.read(min(64 * 1024, self.member_bytes - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    self.used += len(chunk)
                    if count > self.member_bytes or self.used > self.total_bytes:
                        raise ValueError('stream_size_limit')
                    output.write(chunk)
            return str(target)
        except Exception as error:
            if created:
                target.unlink(missing_ok=True)
            return self.reject(name, error)

    def report(self):
        return {'status': 'partial' if self.skipped else 'ok', 'extracted_members': self.count,
                'bytes_read': self.used, 'skipped': self.skipped, 'errors': list(self.errors),
                'limits': {'member_bytes': self.member_bytes, 'total_bytes': self.total_bytes,
                           'members': self.members, 'compression_ratio': self.ratio}}


def create_workspace(output_dir=None):
    parent = Path(output_dir or Path.cwd() / 'sc0pe_reports' / 'android-static')
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='analysis-', dir=str(parent.resolve())))
