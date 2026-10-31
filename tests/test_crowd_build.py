"""Offline crowd-build boundaries; no network or existing private identities."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


manifest = module('crowd_manifest', 'crowd_manifest.py')
promoter = module('promoter_verify', 'promoter_verify.py')
packer = module('crowd_zip', 'crowd_zip.py')
VALID = {'recipe': 'selftest', 'repo': 'https://github.com/yougame-co/build', 'sha': 'a' * 40}


def block(text, name, indent):
    """Read an indentation-delimited mapping from our deliberately simple YAML."""
    lines = text.splitlines()
    start = lines.index(' ' * indent + name + ':') + 1
    end = start
    while end < len(lines):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith('#') and len(line) - len(line.lstrip()) <= indent:
            break
        end += 1
    return '\n'.join(lines[start:end])


def run_blocks(text):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(r'\s+run: \|', line):
            continue
        indent = len(line) - len(line.lstrip())
        body = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following[indent + 2:])
        yield '\n'.join(body) + '\n'


class ManifestTests(unittest.TestCase):
    def test_accepts_exact_schema_and_canonicalizes(self):
        raw = json.dumps(VALID, indent=4)
        canonical = manifest.canonical_manifest(raw)
        self.assertEqual(canonical, json.dumps(VALID, sort_keys=True, separators=(',', ':')).encode())
        self.assertEqual(canonical, manifest.canonical_manifest(canonical))
        self.assertEqual(json.loads(manifest.canonical_manifest((ROOT / 'manifests/selftest.json').read_bytes()))['sha'], '0' * 40)

    def test_rejects_invalid_fields(self):
        cases = [None, [], {}, {**VALID, 'extra': 1}, {k: v for k, v in VALID.items() if k != 'sha'}]
        for recipe in ['../selftest', 'Selftest', '-selftest', 'x' * 42, 'selftest\n', 'missing', '', 12]:
            cases.append({**VALID, 'recipe': recipe})
        for repo in ['http://github.com/a/b', 'https://example.com/a/b', 'https://github.com/a/b.git/x',
                     'https://user@github.com/a/b', 'https://github.com/a/b?x=y', 'https://github.com/a/b\n', 1]:
            cases.append({**VALID, 'repo': repo})
        for sha in ['A' * 40, 'a' * 39, 'a' * 41, 'g' * 40, 'main', 'a' * 40 + '\n', 123]:
            cases.append({**VALID, 'sha': sha})
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                manifest.canonical_manifest(json.dumps(value))

    def test_accepts_recipe_name_boundaries_and_allowed_repo_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            recipes = Path(directory)
            for recipe in ['0', 'a' * 41, 'a-1']:
                (recipes / (recipe + '.sh')).write_text('unused')
                value = {**VALID, 'recipe': recipe, 'repo': 'https://github.com/Owner_1.Name/Repo-2.git'}
                self.assertEqual(json.loads(manifest.canonical_manifest(json.dumps(value), recipes)), value)

    def test_rejects_duplicate_keys_invalid_json_and_symlink_recipe(self):
        for raw in ['{', 'NaN', '{"recipe":"selftest","recipe":"selftest","repo":"https://github.com/a/b","sha":"' + 'a' * 40 + '"}']:
            with self.assertRaises(ValueError):
                manifest.canonical_manifest(raw)
        with tempfile.TemporaryDirectory() as directory:
            recipes = Path(directory)
            (recipes / 'target').write_text('unused')
            (recipes / 'selftest.sh').symlink_to(recipes / 'target')
            with self.assertRaises(ValueError):
                manifest.canonical_manifest(json.dumps(VALID), recipes)

    def test_manifest_paths_stay_in_repo(self):
        for value in ['/tmp/test.json', '../manifests/selftest.json', 'manifests/../keys/test.json',
                      'manifests/nested/test.json', 'manifests/test.txt', 'manifests/test.json\n']:
            with self.subTest(path=value), self.assertRaises(ValueError):
                manifest.manifest_path(value)
        self.assertEqual(manifest.manifest_path('manifests/selftest.json'), ROOT / 'manifests/selftest.json')

    def test_cli_writes_validated_outputs_only(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'github-output'
            with patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(manifest.main(['manifests/selftest.json']), 0)
            fields = dict(line.split('=', 1) for line in output.read_text().splitlines())
            canonical = manifest.canonical_manifest((ROOT / 'manifests/selftest.json').read_bytes())
            self.assertEqual(fields['manifest'].encode(), canonical)
            self.assertEqual(fields['manifest_digest'], hashlib.sha256(canonical).hexdigest())
            self.assertEqual(fields['recipe'], 'selftest')
            before = output.read_bytes()
            with patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(manifest.main(['../invalid.json']), 1)
            self.assertEqual(output.read_bytes(), before)

    def test_cli_error_is_short_specific_and_does_not_echo_input(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(manifest.main(['manifests/../../untrusted-input.json']), 1)
        self.assertEqual(error.getvalue(), 'manifest validation failed: manifest path must be manifests/<name>.json\n')


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / '.github/workflows/crowd-build.yml').read_text()
        cls.jobs = block(cls.text, 'jobs', 0)
        cls.build = block(cls.jobs, 'build', 2)
        cls.attest = block(cls.jobs, 'attest', 2)

    def test_triggers_jobs_permissions_and_timeouts(self):
        self.assertEqual(re.findall(r'^  ([\w-]+):', block(self.text, 'on', 0), re.M), ['workflow_dispatch', 'workflow_call'])
        self.assertEqual(re.findall(r'^  ([\w-]+):', self.jobs, re.M), ['build', 'attest'])
        self.assertEqual(block(self.build, 'permissions', 4).strip(), 'contents: read')
        self.assertEqual(dict(re.findall(r'^      ([\w-]+): (.+)$', block(self.attest, 'permissions', 4), re.M)),
                         {'contents': 'read', 'id-token': 'write', 'attestations': 'write'})
        self.assertIn('    needs: build', self.attest)
        for job, timeout in [(self.build, 30), (self.attest, 10)]:
            self.assertIn(f'    timeout-minutes: {timeout}', job)
            self.assertIn('    runs-on: ubuntu-latest', job)
        self.assertIn('permissions: {}', self.text)
        self.assertNotRegex(self.text, r'(?m)^\s*(?:secrets|environment):|\bsecrets\.')

    def test_pinned_github_actions_no_cache_and_safe_checkouts(self):
        refs = re.findall(r'\buses: (\S+)', self.text)
        expected = {
            'actions/checkout': '3d3c42e5aac5ba805825da76410c181273ba90b1',
            'actions/upload-artifact': 'cf430e030ddbb5b0abf93d22962f4752f3646cd9',
            'actions/download-artifact': '9000827ccba6bdab643e8b6fd33ac0654aef8333',
            'actions/attest-build-provenance': '4d101475d8b20a2381f78447822ac1eab6504dd8',
        }
        self.assertEqual(len(refs), 6)
        for ref in refs:
            self.assertRegex(ref, r'^actions/[a-z-]+@[0-9a-f]{40}$')
            name, sha = ref.split('@')
            self.assertEqual(expected[name], sha)
        self.assertNotIn('actions/cache', self.text)
        for job in [self.build, self.attest]:
            self.assertEqual(job.count('repository: yougame-co/build'), 1)
            self.assertEqual(job.count('ref: ${{ github.workflow_sha }}'), 1)
            self.assertEqual(job.count('persist-credentials: false'), 1)
        self.assertEqual(len(re.findall(r'uses: \S+ # v\d+\.\d+\.\d+', self.text)), len(refs))

    def test_validation_before_fetch_and_privilege_separation(self):
        self.assertLess(self.build.index('scripts/crowd_manifest.py'), self.build.index('git init'))
        self.assertLess(self.build.index('git init'), self.build.index('fetch --depth 1 origin "$SOURCE_SHA"'))
        self.assertLess(self.build.index('checkout --detach FETCH_HEAD'), self.build.index('bash "scripts/recipes/'))
        self.assertNotIn('id-token', self.build)
        self.assertNotIn('attestations:', self.build)
        self.assertNotIn('attest-build-provenance', self.build)
        for forbidden in ['SOURCE_REPO', 'SOURCE_SHA', 'git fetch', 'git init', 'scripts/recipes/', 'bash "', 'unzip']:
            self.assertNotIn(forbidden, self.attest)
        for script in run_blocks(self.text):
            self.assertNotIn('${{ inputs.', script)
            self.assertNotIn('${{', script)
            result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            if "<<'PY'" in script:
                compile(script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0], '<workflow>', 'exec')

    def test_encrypt_before_only_build_upload_and_attest_ciphertext(self):
        self.assertIn('retention-days: 1', self.build)
        self.assertEqual(self.build.count('uses: actions/upload-artifact@'), 1)
        self.assertIn('path: ${{ runner.temp }}/build.zip.age\n', self.build)
        self.assertLess(self.build.index('ref: ${{ github.workflow_sha }}'), self.build.index('bash "scripts/recipes/'))
        self.assertLess(self.build.index('scripts/crowd_zip.py'), self.build.index('apt-get install -y age'))
        self.assertLess(self.build.index('test -s keys/artifacts.age.pub'), self.build.index('age -R keys/artifacts.age.pub'))
        self.assertLess(self.build.index('apt-get install -y age'), self.build.index('age -R keys/artifacts.age.pub'))
        self.assertLess(self.build.index('age -R keys/artifacts.age.pub'), self.build.index('uses: actions/upload-artifact@'))
        self.assertIn('age -R keys/artifacts.age.pub -o "$RUNNER_TEMP/build.zip.age" "$RUNNER_TEMP/build.zip"', self.build)
        self.assertIn('retention-days: 7', self.attest)
        self.assertIn('subject-path: ${{ runner.temp }}/crowd-release/build.zip.age\n', self.attest)
        self.assertLess(self.attest.index('sha256sum build.zip.age'), self.attest.index('uses: actions/attest-build-provenance@'))
        self.assertLess(self.attest.index('uses: actions/attest-build-provenance@'), self.attest.index('uses: actions/upload-artifact@'))
        for forbidden in ['apt-get', 'age -R', 'age -d']:
            self.assertNotIn(forbidden, self.attest)
        upload = self.attest.split('uses: actions/upload-artifact@', 1)[1]
        paths = re.findall(r'^            \$\{\{ runner.temp \}\}/crowd-release/(.+)$', upload, re.M)
        self.assertEqual(paths, ['build.zip.age', 'build.zip.age.sha256', 'manifest.json'])
        names = re.findall(r'name: (crowd-handoff-.+)', self.text)
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0], names[1])

    def test_every_upload_path_is_ciphertext_checksum_or_manifest(self):
        uploads = re.findall(r'uses: actions/upload-artifact@.*?(?=^      - |^  \w|\Z)', self.jobs, re.M | re.S)
        self.assertEqual(len(uploads), 2)
        for upload in uploads:
            match = re.search(r'^          path: (.+)$', upload, re.M)
            self.assertIsNotNone(match)
            if match[1] == '|':
                paths = re.findall(r'^            (\S.*)$', upload, re.M)
            else:
                paths = [match[1]]
            self.assertTrue(paths)
            for path in paths:
                self.assertRegex(path, r'(?:\.age|\.sha256|/manifest\.json)$')


class ZipTests(unittest.TestCase):
    def test_fixed_metadata_sorted_order_and_reproducible_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'output'
            output.mkdir()
            (output / 'z').write_bytes(b'z')
            (output / 'a').write_bytes(b'a')
            (output / 'a').chmod(0o755)
            packer.pack(output, root / 'first.zip')
            os.utime(output / 'a', (1234567890, 1234567890))
            packer.pack(output, root / 'second.zip')
            self.assertEqual((root / 'first.zip').read_bytes(), (root / 'second.zip').read_bytes())
            with zipfile.ZipFile(root / 'first.zip') as archive:
                self.assertEqual(archive.namelist(), ['a', 'z'])
                self.assertEqual(archive.getinfo('a').date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual((archive.getinfo('a').external_attr >> 16) & 0o777, 0o755)
            (output / 'link').symlink_to(root / 'first.zip')
            with self.assertRaises(ValueError):
                packer.pack(output, root / 'bad.zip')

    @unittest.skipUnless(shutil.which('cc'), 'cc is unavailable')
    def test_selftest_recipe_compiles_fixture_and_packs_it(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            subprocess.run(['bash', str(ROOT / 'scripts/recipes/selftest.sh'), str(ROOT), str(output)], check=True, capture_output=True)
            result = subprocess.run([str(output / 'hello')], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout, 'YouGame crowd build self-test\n')
            packer.pack(output, Path(directory) / 'build.zip')
            with zipfile.ZipFile(Path(directory) / 'build.zip') as archive:
                self.assertEqual(archive.namelist(), ['hello'])


class PromoterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / 'artifact'
        self.artifact.mkdir()
        self.data = b'opaque zip bytes: verification must not extract these'
        self.digest = hashlib.sha256(self.data).hexdigest()
        (self.artifact / 'build.zip.age').write_bytes(b'fake ciphertext')
        self.cipher_digest = promoter.sha256(self.artifact / 'build.zip.age')
        (self.artifact / 'build.zip.age.sha256').write_text(self.cipher_digest + '  build.zip.age\n')
        (self.artifact / 'manifest.json').write_text(json.dumps(VALID))
        self.expected = self.root / 'expected.json'
        self.expected.write_text(json.dumps(VALID, indent=4))
        # Fakes only receive this nonexistent path; no private file is opened.
        self.identity = self.root / 'unused-identity'
        self.calls = []
        self.staging = []
        self.stdout, self.stderr = io.StringIO(), io.StringIO()

    def fake_command(self, args):
        self.calls.append(args)
        if args[0] == 'age':
            target = Path(args[args.index('-o') + 1])
            self.assertEqual(list(target.parent.iterdir()), [])
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(args[args.index('-i') + 1], str(self.identity))
            self.staging.append(target.parent)
            self.addCleanup(shutil.rmtree, target.parent, True)
            target.write_bytes(self.data)

    def invoke(self, fake=None):
        with patch.object(promoter, 'command', side_effect=fake or self.fake_command), \
                contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return promoter.verify(self.artifact, self.expected, self.identity)

    def test_success_order_and_exact_attestation_policy(self):
        events = []
        real_sha256 = promoter.sha256
        real_canonical = promoter.canonical_manifest

        def fake(args):
            events.append(args[0])
            self.fake_command(args)

        def hash_zip(path):
            events.append('sha256')
            return real_sha256(path)

        def canonical(raw):
            events.append('manifest')
            return real_canonical(raw)

        with patch.object(promoter, 'sha256', side_effect=hash_zip), patch.object(promoter, 'canonical_manifest', side_effect=canonical):
            self.assertEqual(self.invoke(fake), 0)
        self.assertEqual(events, ['sha256', 'gh', 'manifest', 'manifest', 'age', 'sha256'])
        zip_path = self.staging[0] / 'build.zip'
        self.assertEqual(self.calls[0], ['gh', 'attestation', 'verify', str(self.artifact / 'build.zip.age'),
                         '--repo', 'yougame-co/build', '--signer-workflow',
                         'yougame-co/build/.github/workflows/crowd-build.yml', '--source-ref',
                         'refs/heads/main', '--deny-self-hosted-runners', '--format', 'json'])
        self.assertEqual(self.stdout.getvalue(), f'VERIFIED {zip_path} {self.digest}\n')
        self.assertEqual(self.stderr.getvalue(), '')
        self.assertEqual(zip_path.read_bytes(), self.data)

    def test_failures_stop_at_each_step_and_remove_plaintext(self):
        for step in ['sha256', 'attestation', 'manifest', 'decrypt', 'plaintext-hash']:
            with self.subTest(step=step):
                self.calls.clear()
                self.staging.clear()
                self.stdout.truncate(0)
                self.stdout.seek(0)
                self.stderr.truncate(0)
                self.stderr.seek(0)
                (self.artifact / 'build.zip.age.sha256').write_text(('0' * 64 if step == 'sha256' else self.cipher_digest) + '  build.zip.age\n')
                (self.artifact / 'manifest.json').write_text(json.dumps({**VALID, 'sha': 'b' * 40} if step == 'manifest' else VALID))

                def fake(args):
                    self.fake_command(args)
                    if (args[0] == 'age' and step == 'decrypt') or (args[0] == 'gh' and step == 'attestation'):
                        raise RuntimeError('tool diagnostics and identity paths must never escape')
                    if args[0] == 'age' and step == 'plaintext-hash':
                        Path(args[args.index('-o') + 1]).unlink()

                self.assertEqual(self.invoke(fake), 1)
                self.assertEqual(self.stdout.getvalue(), '')
                self.assertEqual(self.stderr.getvalue(), 'FAILED ' + ('decrypt' if step == 'plaintext-hash' else step) + '\n')
                self.assertTrue(all(not folder.exists() for folder in self.staging))
                self.assertEqual([args[0] for args in self.calls], [] if step == 'sha256' else ['gh'] if step in ['attestation', 'manifest'] else ['gh', 'age'])
                if step in ['sha256', 'attestation', 'manifest']:
                    self.assertEqual(self.staging, [])

    def test_rejects_checksum_filename_confusion_and_manifest_duplicates(self):
        (self.artifact / 'build.zip.age.sha256').write_text(self.cipher_digest + '  other.zip\n')
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.calls, [])
        self.assertTrue(all(not folder.exists() for folder in self.staging))
        (self.artifact / 'build.zip.age.sha256').write_text(self.cipher_digest + '  build.zip.age\n')
        (self.artifact / 'manifest.json').write_text(json.dumps(VALID)[:-1] + ',"recipe":"selftest"}')
        self.assertEqual(self.invoke(), 1)
        self.assertEqual([args[0] for args in self.calls], ['gh'])
        self.assertEqual(self.staging, [])

    def test_missing_ciphertext_never_creates_temp_or_runs_tools(self):
        (self.artifact / 'build.zip.age').unlink()
        with patch.object(promoter.tempfile, 'mkdtemp') as mkdtemp:
            self.assertEqual(self.invoke(), 1)
        mkdtemp.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.stderr.getvalue(), 'FAILED sha256\n')

    def test_subprocess_diagnostics_are_suppressed(self):
        with patch.object(promoter.subprocess, 'run') as run:
            promoter.command(['age', '-d', '-i', 'throwaway-path'])
        self.assertEqual(run.call_args.kwargs, {'check': True, 'stdin': subprocess.DEVNULL,
                         'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL})

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age tools are unavailable')
    def test_real_throwaway_age_round_trip_with_fake_gh(self):
        self.identity = self.root / 'throwaway.agekey'
        subprocess.run(['age-keygen', '-o', str(self.identity)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Pass throwaway key material between age tools by file path only.
        recipients = self.root / 'throwaway-recipients'
        with recipients.open('wb') as output:
            subprocess.run(['age-keygen', '-y', str(self.identity)], check=True,
                           stdout=output, stderr=subprocess.DEVNULL)
        plain = self.root / 'plain.zip'
        plain.write_bytes(self.data)
        (self.artifact / 'build.zip.age').unlink()
        subprocess.run(['age', '-R', str(recipients), '-o', str(self.artifact / 'build.zip.age'), str(plain)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (self.artifact / 'build.zip.age.sha256').write_text(
            promoter.sha256(self.artifact / 'build.zip.age') + '  build.zip.age\n')
        actual_command = promoter.command
        events = []

        def fake_gh(args):
            events.append(args[0])
            if args[0] == 'age':
                target = Path(args[args.index('-o') + 1])
                self.staging.append(target.parent)
                self.addCleanup(shutil.rmtree, target.parent, True)
                actual_command(args)
            else:
                self.assertEqual(args[:3], ['gh', 'attestation', 'verify'])

        self.assertEqual(self.invoke(fake_gh), 0)
        self.assertEqual(events, ['gh', 'age'])
        self.assertEqual((self.staging[0] / 'build.zip').read_bytes(), self.data)


if __name__ == '__main__':
    unittest.main()
