#!/usr/bin/env python3
"""Verify a downloaded crowd artifact locally; never extract or publish it."""
import argparse
import hashlib
import json
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


def command(args, *, capture=False):
    # Neither the identity path nor tool diagnostics belong in public output.
    result = subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return result.stdout if capture else None


def require_bound_statement(raw, ciphertext_digest, manifest_digest, invocation_id):
    """Use only gh's verified statements; never combine subjects across statements."""
    results = json.loads(raw)
    if not isinstance(results, list) or not results:
        raise ValueError('missing verified statement')
    for result in results:
        statement = result['verificationResult']['statement']
        if statement['predicateType'] != 'https://slsa.dev/provenance/v1':
            continue
        actual_invocation = statement['predicate']['runDetails']['metadata']['invocationId']
        subjects = statement['subject']
        if not isinstance(subjects, list):
            raise ValueError('invalid attestation subjects')
        digests = {subject['digest'].get('sha256') for subject in subjects}
        if actual_invocation == invocation_id and {ciphertext_digest, manifest_digest} <= digests:
            return
    raise ValueError('attestation does not bind files to requested run and attempt')


def verify(artifact, expected_manifest, identity, *, run_id, run_attempt, run_conclusion):
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
        if run_conclusion != 'success':
            raise ValueError('run did not succeed')
        if not all(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value)
                   for value in (run_id, run_attempt)):
            raise ValueError('invalid run id or attempt')
        invocation_id = f'https://github.com/yougame-co/build/actions/runs/{run_id}/attempts/{run_attempt}'
        manifest_bytes = regular_file(Path(artifact) / 'manifest.json').read_bytes()
        verified = command(['gh', 'attestation', 'verify', str(ciphertext),
                 '--repo', 'yougame-co/build',
                 '--signer-workflow', 'yougame-co/build/.github/workflows/crowd-build.yml',
                 '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners',
                 '--format', 'json'], capture=True)
        require_bound_statement(verified, digest, hashlib.sha256(manifest_bytes).hexdigest(), invocation_id)

        step = 'manifest'
        actual = canonical_manifest(manifest_bytes)
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
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog='Use the run and attempt you downloaded. Obtain the conclusion with: '
               'gh run view <run-id> --repo yougame-co/build --attempt <run-attempt> '
               '--json conclusion --jq .conclusion')
    parser.add_argument('artifact', type=Path, help='downloaded encrypted artifact folder')
    parser.add_argument('manifest', type=Path, help='expected manifest file')
    parser.add_argument('identity', type=Path, help='age private key path (opened only by age)')
    parser.add_argument('--run-id', required=True, help='GitHub run ID used for the artifact download')
    parser.add_argument('--run-attempt', required=True, help='GitHub run attempt used for the artifact download')
    parser.add_argument('--run-conclusion', required=True, help='conclusion from gh run view (must be success)')
    args = parser.parse_args(argv)
    return verify(args.artifact, args.manifest, args.identity, run_id=args.run_id,
                  run_attempt=args.run_attempt, run_conclusion=args.run_conclusion)


if __name__ == '__main__':
    sys.exit(main())
