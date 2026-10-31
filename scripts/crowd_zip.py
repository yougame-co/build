#!/usr/bin/env python3
"""Pack regular recipe outputs in sorted order with fixed ZIP metadata."""
from pathlib import Path
import shutil
import stat
import sys
import zipfile


def pack(source, destination):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('output must be a directory')
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(source.rglob('*')):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ValueError('output must contain only regular files and directories')
            info = zipfile.ZipInfo(path.relative_to(source).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if mode & 0o111 else 0o644)) << 16
            with path.open('rb') as source_file, archive.open(info, 'w', force_zip64=True) as zip_file:
                shutil.copyfileobj(source_file, zip_file)


if __name__ == '__main__':
    pack(sys.argv[1], sys.argv[2])
