#!/usr/bin/env python3
"""Verify a downloaded crowd artifact locally; never extract or publish it."""
import argparse
import hashlib
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

canonical_manifest = runpy.run_path(str(Path(__file__).with_name('crowd_manifest.py')))['canonical_manifest']


def regular_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing or nonregular artifact file')
    return path


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def command(args):
    # Neither the identity path nor tool diagnostics belong in public output.
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify(artifact, expected_manifest, identity):
    """Leave the decrypted zip only on success. The caller owns its cleanup."""
    folder = None
    step = 'sha256'
    try:
        ciphertext = regular_file(Path(artifact) / 'build.zip.age')
        digest = sha256(ciphertext)
        checksum = regular_file(Path(artifact) / 'build.zip.age.sha256').read_text(encoding='ascii')
        if not re.fullmatch(r'[0-9a-f]{64}  build\.zip\.age\n?', checksum) or checksum[:64] != digest:
            raise ValueError('ciphertext digest mismatch')

        step = 'attestation'
        command(['gh', 'attestation', 'verify', str(ciphertext),
                 '--repo', 'yougame-co/build',
                 '--signer-workflow', 'yougame-co/build/.github/workflows/crowd-build.yml',
                 '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners',
                 '--format', 'json'])

        step = 'manifest'
        actual = canonical_manifest(regular_file(Path(artifact) / 'manifest.json').read_bytes())
        expected = canonical_manifest(Path(expected_manifest).read_bytes())
        if actual != expected or hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest():
            raise ValueError('manifest mismatch')

        step = 'decrypt'
        folder = Path(tempfile.mkdtemp(prefix='yougame-crowd-verified-'))
        zip_path = folder / 'build.zip'
        # The age process alone opens the private key by path. Python never reads it.
        command(['age', '-d', '-i', str(identity), '-o', str(zip_path), str(ciphertext)])
        digest = sha256(regular_file(zip_path))
        print(f'VERIFIED {zip_path} {digest}')
        return 0
    except (Exception, KeyboardInterrupt):
        if folder is not None:
            try:
                shutil.rmtree(folder)
            except OSError:
                print('FAILED ' + step + ' (temporary cleanup failed)', file=sys.stderr)
                return 1
        print('FAILED ' + step, file=sys.stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path, help='downloaded encrypted artifact folder')
    parser.add_argument('manifest', type=Path, help='expected manifest file')
    parser.add_argument('identity', type=Path, help='age private key path (opened only by age)')
    args = parser.parse_args(argv)
    return verify(args.artifact, args.manifest, args.identity)


if __name__ == '__main__':
    sys.exit(main())
