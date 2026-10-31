import base64
"""Offline safety/lifecycle checks; no Azure commands or real credentials."""
import contextlib
import datetime as dt
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('boxes', Path(__file__).parents[1] / 'scripts/test-boxes.py')
boxes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boxes)
NOW = dt.datetime(2026, 10, 31, tzinfo=dt.timezone.utc)


class CaptureTime(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.replace(hour=12, minute=34, second=56)


def resource(name, kind=boxes.VM_TYPE, **tags):
    return {'name': name, 'id': '/mock/' + name, 'type': kind,
            'createdTime': (NOW - dt.timedelta(hours=1)).isoformat(),
            'tags': {'owner': 'agent', 'expires': (NOW + dt.timedelta(hours=1)).isoformat(), **tags}}


class LifecycleTests(unittest.TestCase):
    @contextlib.contextmanager
    def capture_case(self, missing=(), scan='YG_NO_DISC', stderr='', entries=None,
                     data_disks=(), fail_version=False, items=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm = resource('ygbox-test-123', box='ygbox-test-123', image_builder='yes')
            vm['location'] = 'eastus'
            calls = []
            version = []

            def fake_az(*args, timeout=None):
                calls.append(args)
                if args[:2] == ('vm', 'show'):
                    return {'storageProfile': {'dataDisks': list(data_disks)}}
                if args[:2] == ('vm', 'get-instance-view'):
                    return {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Ready'}]}}}
                if args[:3] == ('vm', 'run-command', 'invoke'):
                    self.assertEqual(timeout, 900)
                    return {'value': entries if entries is not None else [
                        {'code': 'ComponentStatus/StdOut/succeeded', 'message': scan},
                        {'code': 'ComponentStatus/StdErr/succeeded', 'message': stderr}]}
                if args[:2] == ('sig', 'show'):
                    if 'gallery' in missing:
                        raise RuntimeError('missing gallery')
                    return {'id': '/mock/gallery'}
                if args[:2] == ('sig', 'create'):
                    return {'id': '/mock/gallery'}
                if args[:3] == ('sig', 'image-definition', 'show'):
                    if 'definition' in missing:
                        raise RuntimeError('missing definition')
                    return {'id': '/mock/definition'}
                if args[:3] == ('sig', 'image-definition', 'create'):
                    return {'id': '/mock/definition'}
                if args[:3] == ('sig', 'image-version', 'create'):
                    if fail_version:
                        raise RuntimeError('capture failed')
                    version.append(args[args.index('--gallery-image-version') + 1])
                    return {}
                if args[:3] == ('sig', 'image-version', 'list'):
                    return [{'name': n} for n in ['1.20260101.10', version[0],
                                                  '1.20260101.9', '1.20260101.11']]
                return {}

            env = {'GITHUB_RUN_ID': '123', 'AZURE_RESOURCE_GROUP': 'mock',
                   'GITHUB_OUTPUT': str(root/'output'), 'GITHUB_STEP_SUMMARY': str(root/'summary')}
            with patch.dict(os.environ, env), patch.object(boxes, 'login') as login, patch.object(boxes, 'az', side_effect=fake_az), patch.object(boxes, 'inventory', return_value=[vm] if items is None else items), patch.object(boxes.dt, 'datetime', CaptureTime), patch.object(boxes.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()) as output:
                yield root, calls, vm, version, login, output

    def test_capture_validates_before_login(self):
        valid = {'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'}
        cases = [({'no_disc': 'no'}, 'Refusing capture: confirm no game disc, ROM or signed-in account is on the box'),
                 ({'no_disc': ''}, 'Refusing capture: confirm no game disc, ROM or signed-in account is on the box'),
                 ({'name': 'invalid'}, 'Invalid box name')]
        cases += [({'image': image}, 'Invalid image name')
                  for image in ['', '-bad', 'bad-', 'Upper', 'x' * 33, 'bad\nname']]
        with patch.object(boxes, 'login') as login, patch.object(boxes, 'az') as az:
            for changes, error in cases:
                with self.subTest(changes=changes), self.assertRaisesRegex(boxes.ValidationError, error):
                    boxes.capture({**valid, **changes})
            with self.assertRaisesRegex(boxes.ValidationError, 'confirm no game disc'):
                boxes.capture({'name': valid['name'], 'image': valid['image']})
            login.assert_not_called()
            az.assert_not_called()

    def test_capture_refuses_missing_or_unowned_vm(self):
        for items in [[], [resource('ygbox-test-123', owner='human')],
                      [resource('ygbox-test-123', 'microsoft.compute/galleries/images', owner='agent-image')]]:
            with self.subTest(items=items), self.capture_case(items=items) as case:
                with self.assertRaisesRegex(boxes.ValidationError, 'VM must exist and have owner=agent'):
                    boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
                self.assertEqual(case[1], [])

    def test_capture_disc_guard_fails_before_deallocation(self):
        for scan, stderr in [('x YG_NO_DISC', ''), ('YG_NO_DISC\nmore', ''),
                             ('YG_NO_DISC', 'private-scan-detail'), ('YG_NO_DISC', '\n'),
                             ('YG_SCAN_ERROR 1 0', ''), ('YG_DISC_FOUND 0 1', ''),
                             ('YG_DISC_FOUND 1 0 private-scan-detail', ''),
                             ('', ''), ('private-scan-detail', '')]:
            with self.subTest(scan=scan, stderr=stderr), self.capture_case(scan=scan, stderr=stderr) as case:
                with self.assertRaisesRegex(boxes.ValidationError, '^Refusing capture: guest disc scan did not report a clean disk$'):
                    boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
                self.assertEqual([c[:2] for c in case[1]], [('vm', 'show'), ('vm', 'get-instance-view'),
                                                           ('vm', 'run-command')])
                self.assertFalse((case[0]/'output').exists())
                self.assertNotIn('private-scan-detail', case[5].getvalue())
                expected = scan if scan in ('YG_SCAN_ERROR 1 0', 'YG_DISC_FOUND 0 1') else 'other'
                if scan.startswith('YG_DISC_FOUND 1 0'):
                    expected = 'YG_DISC_FOUND 1 0'
                self.assertEqual(case[5].getvalue().splitlines()[-1], 'guest scan: ' + expected)

    def test_capture_requires_exactly_one_stdout_and_stderr_entry(self):
        stdout = {'code': 'ComponentStatus/StdOut/succeeded', 'message': 'YG_NO_DISC'}
        stderr = {'code': 'ComponentStatus/StdErr/succeeded', 'message': ''}
        for entries in [[], [stdout], [stderr], [stdout, stdout, stderr], [stdout, stderr, stderr],
                        [stdout, stderr, {'code': 'other', 'message': ''}],
                        [None, stderr], [stdout, {'code': None, 'message': ''}],
                        [{'code': 'ComponentStatus/StdOut/failed', 'message': 'YG_NO_DISC'}, stderr],
                        [{'message': 'YG_NO_DISC'}, stderr],
                        [{'code': stdout['code']}, stderr],
                        [stdout, {'code': stderr['code']}],
                        [{'code': stdout['code'], 'message': None}, stderr]]:
            with self.subTest(entries=entries), self.capture_case(entries=entries) as case:
                with self.assertRaisesRegex(boxes.ValidationError, 'guest disc scan did not report a clean disk'):
                    boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
                self.assertFalse(any(c[:2] == ('vm', 'deallocate') for c in case[1]))

    def test_capture_accepts_only_clean_stdout_and_empty_stderr_by_code(self):
        for scan in ['YG_NO_DISC', ' \r\nYG_NO_DISC\r\n ']:
            entries = [{'code': 'ComponentStatus/StdErr/succeeded', 'message': ''},
                       {'code': 'ComponentStatus/StdOut/succeeded', 'message': scan}]
            with self.subTest(scan=scan), self.capture_case(entries=entries) as case:
                boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
                self.assertTrue(any(c[:2] == ('vm', 'deallocate') for c in case[1]))

    def test_capture_requires_image_builder_tag(self):
        for tags in [None, {}, {'image_builder': 'no'}, {'image_builder': 'YES'}]:
            with self.subTest(tags=tags), self.capture_case() as case:
                vm = case[2]
                vm['tags'] = {'owner': 'agent', **(tags or {})}
                with self.assertRaisesRegex(boxes.ValidationError, '^Refusing capture: only a box created with image_builder=yes can be captured$'):
                    boxes.capture({'name': vm['name'], 'image': 'prepared', 'no_disc': 'yes'})
                self.assertEqual(case[1], [])
                self.assertFalse((case[0]/'output').exists())

    def test_capture_refuses_data_disks_before_scanning_or_deallocation(self):
        with self.capture_case(data_disks=[{'name': 'data', 'lun': 0}]) as case:
            with self.assertRaisesRegex(boxes.ValidationError, '^Refusing capture: data disks are not captured or cleaned$'):
                boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
            self.assertEqual([c[:2] for c in case[1]], [('vm', 'show')])
            self.assertFalse((case[0]/'output').exists())

    def test_disc_scan_walks_whole_os_volume_and_fails_closed(self):
        scan = boxes.DISC_SCAN
        for text in ["$ErrorActionPreference = 'Stop'", 'Stack[string]', "$stack.Push('C:\\')",
                     '$stack.Pop()', '[System.IO.DirectoryInfo]::new($dir).EnumerateFileSystemInfos()',
                     'if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }',
                     '$entry.Extension.ToLowerInvariant()', '$entry.Length -gt 1GB',
                     '$systemFiles -notcontains $entry.FullName.ToLowerInvariant()',
                     'c:\\pagefile.sys', 'c:\\swapfile.sys', 'c:\\hiberfil.sys',
                     '} catch {\n        $errors++',
                     "if ($errors -gt 0) { Write-Output ('YG_SCAN_ERROR '",
                     "elseif ($found -gt 0) { Write-Output ('YG_DISC_FOUND '",
                     "else { Write-Output 'YG_NO_DISC' }"]:
            self.assertIn(text, scan)
        for extension in ['.iso', '.gcm', '.rvz', '.ciso', '.wbfs', '.wia', '.gcz', '.nkit', '.dol', '.elf', '.rom']:
            self.assertIn("'" + extension + "'", scan)
        self.assertNotIn('SilentlyContinue', scan)
        self.assertEqual(scan.count('Write-Output'), 3)

    def test_capture_creates_specialized_image_and_keeps_newest_two(self):
        for missing in [(), ('gallery',), ('definition',), ('gallery', 'definition')]:
            with self.subTest(missing=missing), self.capture_case(missing=missing) as case:
                root, calls, vm, version, login, output = case
                boxes.capture({'name': vm['name'], 'image': 'prepared', 'no_disc': 'yes'})
                login.assert_called_once()
                self.assertEqual(calls[0][:2], ('vm', 'show'))
                self.assertEqual(sum(c[:2] == ('vm', 'show') for c in calls), 1)
                self.assertEqual(calls[1][:2], ('vm', 'get-instance-view'))
                self.assertEqual(calls[2][:3], ('vm', 'run-command', 'invoke'))
                self.assertEqual(calls[2][-1], boxes.DISC_SCAN)
                self.assertEqual(calls[3][:2], ('vm', 'deallocate'))
                self.assertEqual(calls[4][:2], ('sig', 'show'))
                self.assertEqual(sum(c[:2] == ('sig', 'create') for c in calls), int('gallery' in missing))
                definitions = [c for c in calls if c[:3] == ('sig', 'image-definition', 'create')]
                self.assertEqual(len(definitions), int('definition' in missing))
                if definitions:
                    for flag, value in [('--os-type', 'Windows'), ('--os-state', 'Specialized'),
                                        ('--hyper-v-generation', 'V2'), ('--features', 'SecurityType=Standard'),
                                        ('--publisher', 'yougame'), ('--offer', 'testbox'), ('--sku', 'prepared')]:
                        self.assertEqual(definitions[0][definitions[0].index(flag) + 1], value)
                create = next(c for c in calls if c[:3] == ('sig', 'image-version', 'create'))
                for flag, value in [('--virtual-machine', vm['id']), ('--target-regions', vm['location']),
                                    ('--replica-count', '1'), ('--storage-account-type', 'Standard_LRS')]:
                    self.assertEqual(create[create.index(flag) + 1], value)
                self.assertRegex(version[0], r'^1\.[0-9]{8}\.[0-9]{6}$')
                self.assertEqual(version[0], '1.20261031.123456')
                tagged = [c for c in calls if '--tags' in c]
                self.assertGreaterEqual(len(tagged), 3)
                for call in tagged:
                    for tag in ['owner=agent-image', 'purpose=image', 'source=' + vm['name'], 'run=123']:
                        self.assertIn(tag, call)
                    self.assertTrue(any(v.startswith('created=') for v in call))
                    self.assertNotIn('owner=agent', call)
                    self.assertNotIn('image_builder=yes', call)
                deleted = [c for c in calls if c[:3] == ('sig', 'image-version', 'delete')]
                self.assertEqual([c[c.index('--gallery-image-version') + 1] for c in deleted],
                                 ['1.20260101.9', '1.20260101.10'])
                self.assertTrue(all(calls.index(c) > calls.index(create) for c in deleted))
                self.assertFalse(any(c[:2] == ('resource', 'delete') for c in calls))
                self.assertEqual((root/'output').read_text(), 'image=prepared\nversion=' + version[0] + '\n')
                for text in [vm['name'], 'image: prepared', 'version: ' + version[0], 'box-down']:
                    self.assertIn(text, output.getvalue())
                    self.assertIn(text, (root/'summary').read_text())
                self.assertNotIn(vm['id'], output.getvalue())

    def test_capture_failure_after_deallocation_keeps_source_and_versions(self):
        with self.capture_case(fail_version=True) as case:
            with self.assertRaisesRegex(RuntimeError, 'capture failed'):
                boxes.capture({'name': 'ygbox-test-123', 'image': 'prepared', 'no_disc': 'yes'})
            calls = case[1]
            self.assertTrue(any(c[:2] == ('vm', 'deallocate') for c in calls))
            self.assertFalse(any('delete' in c or 'start' in c for c in calls))
            self.assertFalse((case[0]/'output').exists())

    @contextlib.contextmanager
    def image_up_case(self, versions):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm = resource('ygbox-test-123', box='ygbox-test-123')
            disk = resource('ygbox-test-123-os', boxes.DISK_TYPE, box='ygbox-test-123')
            calls = []

            def fake_az(*args):
                calls.append(args)
                if args[:3] == ('sig', 'image-version', 'list'):
                    return versions
                if args[:3] == ('network', 'public-ip', 'show'):
                    return {'ipAddress': 'synthetic-address'}
                return {}

            old = os.getcwd()
            try:
                os.chdir(root)
                env = {'GITHUB_RUN_ID': '123', 'AZURE_RESOURCE_GROUP': 'mock',
                       'GITHUB_OUTPUT': str(root/'output'), 'GITHUB_STEP_SUMMARY': str(root/'summary')}
                with patch.dict(os.environ, env), patch.object(boxes, 'login') as login, patch.object(boxes, 'az', side_effect=fake_az), patch.object(boxes, 'inventory', side_effect=[[], [vm, disk], [vm, disk]]), patch.object(boxes.time, 'sleep'), patch.object(boxes, 'wait_guest_agent') as wait, patch.object(boxes.secrets, 'token_urlsafe') as password, contextlib.redirect_stdout(io.StringIO()) as output:
                    inputs = {'label': 'test', 'image': 'prepared', 'os': 'ignored',
                              'allow_cidr': str(boxes.ipaddress.IPv4Address(0x08080808)) + '/32'}
                    yield root, calls, inputs, wait, password, login, output
            finally:
                os.chdir(old)

    def test_up_image_uses_newest_specialized_version_without_guest_setup(self):
        versions = [{'name': n, 'id': '/mock/version/' + n}
                    for n in ['1.20260101.9', '1.20260101.11', '1.20260101.10']]
        with self.image_up_case(versions) as case:
            root, calls, inputs, wait, password, login, output = case
            boxes.up(inputs)
            login.assert_called_once()
            create = next(c for c in calls if c[:2] == ('vm', 'create'))
            self.assertEqual(create[create.index('--image') + 1], versions[1]['id'])
            self.assertIn('--specialized', create)
            for flag in ['--admin-username', '--admin-password', '--computer-name',
                         '--authentication-type', '--ssh-key-values']:
                self.assertNotIn(flag, create)
            for flag, value in [('--security-type', 'Standard'), ('--storage-sku', 'Premium_LRS'),
                                ('--nics', 'ygbox-test-123-nic'), ('--os-disk-name', 'ygbox-test-123-os'),
                                ('--os-disk-delete-option', 'Detach'), ('--nic-delete-option', 'Detach')]:
                self.assertEqual(create[create.index(flag) + 1], value)
            self.assertIn('owner=agent', create)
            self.assertFalse(any(c[:2] in [('vm', 'run-command'), ('vm', 'get-instance-view')] for c in calls))
            wait.assert_not_called()
            password.assert_not_called()
            self.assertIn('os=image:prepared\n', (root/'output').read_text())
            self.assertIn('image prepared 1.20260101.11', output.getvalue())
            self.assertEqual(len([c for c in calls if c[:4] == ('network', 'nsg', 'rule', 'create')]), 3)

    def test_up_image_builder_tags_all_box_resources_only_when_requested(self):
        versions = [{'name': '1.20260101.1', 'id': '/mock/version/1'}]
        for from_image in [False, True]:
            for image_builder in [None, 'no', 'yes']:
                with self.subTest(from_image=from_image, image_builder=image_builder), self.image_up_case(versions) as case:
                    root, calls, inputs = case[:3]
                    if not from_image:
                        (root / 'keys').mkdir()
                        (root / 'keys/agent-ssh.pub').write_text('ssh-ed25519 AAAA synthetic-test\n')
                        inputs.update(image='', os='ubuntu-24.04')
                    if image_builder is not None:
                        inputs['image_builder'] = image_builder
                    boxes.up(inputs)
                    tagged = [c for c in calls if '--tags' in c]
                    self.assertEqual(len(tagged), 6)
                    tags = []
                    for call in tagged:
                        values = []
                        for value in call[call.index('--tags') + 1:]:
                            if value.startswith('--'):
                                break
                            values.append(value)
                        tags.append(values)
                        self.assertEqual('image_builder=yes' in values, image_builder == 'yes')
                        self.assertNotIn('image_builder=no', values)
                    self.assertTrue(all(values == tags[0] for values in tags))

    def test_up_image_without_versions_fails_before_creating_resources(self):
        with self.image_up_case([]) as case:
            with self.assertRaisesRegex(boxes.ValidationError, '^No image version for prepared$'):
                boxes.up(case[2])
            self.assertEqual([c[:3] for c in case[1]], [('sig', 'image-definition', 'show'),
                                                                     ('sig', 'image-version', 'list')])
            self.assertFalse((case[0]/'output').exists())

    def test_up_rejects_invalid_image_before_login(self):
        with patch.object(boxes, 'login') as login:
            with self.assertRaisesRegex(boxes.ValidationError, 'Invalid image name'):
                boxes.up({'image': 'Invalid'})
            login.assert_not_called()

    def test_reaper_ignores_gallery_definition_and_version_image_owners(self):
        images = [resource('ygbox-test-123', kind, owner='agent-image', box='ygbox-test-123', expires='invalid')
                  for kind in ['microsoft.compute/galleries', 'microsoft.compute/galleries/images',
                               'microsoft.compute/galleries/images/versions']]
        for image in images:
            image['createdTime'] = (NOW - dt.timedelta(days=30)).isoformat()
        with patch.object(boxes, 'inventory', return_value=images), patch.object(boxes, 'delete_resources') as delete:
            boxes.reap(NOW)
            delete.assert_called_once_with([])
            with self.assertRaises(boxes.ValidationError):
                boxes.down('ygbox-test-123')
            delete.assert_called_once_with([])

    def test_capture_workflow_reuses_mask_checkout_and_environment(self):
        workflows = Path(__file__).parents[1] / '.github/workflows'
        up = (workflows / 'box-up.yml').read_text()
        capture = (workflows / 'box-image.yml').read_text()
        self.assertEqual(up.split('    env:\n')[1].split('    outputs:\n')[0],
                         capture.split('    env:\n')[1].split('    outputs:\n')[0])
        self.assertEqual(up.split('    steps:\n')[1].replace('test-boxes.py up', 'test-boxes.py capture'),
                         capture.split('    steps:\n')[1])
        for text in ['timeout-minutes: 75', 'environment: test-boxes', 'contents: read',
                     'id-token: write', "options: ['no', 'yes']", "default: 'no'"]:
            self.assertIn(text, capture)
        self.assertEqual(capture.split('on:\n')[1].split('\nconcurrency:')[0].splitlines()[0],
                         '  workflow_dispatch:')
        builder = up.split('      image_builder:\n')[1].split('      size:')[0]
        for text in ['type: choice', 'required: false', "options: ['no', 'yes']", "default: 'no'"]:
            self.assertIn(text, builder)

    def test_missing_key_fails_before_login(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(boxes, 'login') as login:
            old = os.getcwd()
            try:
                os.chdir(directory)
                with self.assertRaisesRegex(boxes.ValidationError, 'keys/agent-ssh.pub missing'):
                    boxes.up({})
                login.assert_not_called()
            finally:
                os.chdir(old)

    def test_reaper_hard_cap_and_expiry_and_untagged_disk(self):
        expired = resource('ygbox-old-1', box='ygbox-old-1', expires=NOW.isoformat())
        ancient = resource('ygbox-ancient-2', expires=(NOW + dt.timedelta(days=1)).isoformat())
        ancient['createdTime'] = (NOW - dt.timedelta(hours=13)).isoformat()
        ancient['tags']['created'] = NOW.isoformat()  # Server age wins.
        fresh = resource('ygbox-fresh-3')
        other = resource('other', owner='human', expires=NOW.isoformat())
        missing = resource('ygbox-missing-4', expires='invalid')
        orphan_disk = resource('ygbox-old-1-os', boxes.DISK_TYPE)
        orphan_disk['tags'] = None
        unrelated_disk = resource('ygbox-old-1-os', boxes.DISK_TYPE, owner='human')
        with patch.object(boxes, 'inventory', return_value=[expired, ancient, fresh, other, missing, orphan_disk, unrelated_disk]), patch.object(boxes, 'delete_resources') as delete:
            boxes.reap(NOW)
        self.assertEqual(delete.call_args.args[0], [expired, ancient, missing, orphan_disk])

    def test_down_refuses_unowned_or_absent_vm(self):
        for items in [[], [resource('ygbox-test-1', owner='human')]]:
            with patch.object(boxes, 'inventory', return_value=items), patch.object(boxes, 'delete_resources') as delete:
                with self.assertRaises(boxes.ValidationError):
                    boxes.down('ygbox-test-1')
                delete.assert_not_called()

    def test_down_deletes_only_box_resources_in_dependency_order(self):
        vm = resource('ygbox-test-1', box='ygbox-test-1')
        nic = resource('ygbox-test-1-nic', 'microsoft.network/networkinterfaces', box='ygbox-test-1')
        disk = resource('ygbox-test-1-os', boxes.DISK_TYPE)
        disk['tags'] = {}
        unrelated = resource('ygbox-another-2', box='ygbox-another-2')
        with patch.object(boxes, 'inventory', return_value=[nic, vm, disk, unrelated]), patch.object(boxes, 'az') as az, contextlib.redirect_stdout(io.StringIO()):
            boxes.down('ygbox-test-1')
        self.assertEqual([c.args[-1] for c in az.call_args_list], [vm['id'], nic['id'], disk['id']])

    def test_inventory_uses_server_creation_time_and_pagination(self):
        base = 'https://management.azure.com/subscriptions/sub/resourceGroups/group/resources'
        with patch.dict(os.environ, {'AZURE_SUBSCRIPTION_ID': 'sub', 'AZURE_RESOURCE_GROUP': 'group'}), patch.object(boxes, 'az', side_effect=[{'value': [1], 'nextLink': base + '?page=2'}, {'value': [2]}]) as az:
            self.assertEqual(boxes.inventory(), [1, 2])
            self.assertIn('$expand=createdTime,changedTime', az.call_args_list[0].args[-1])

    def test_inventory_refuses_foreign_continuation(self):
        with patch.dict(os.environ, {'AZURE_SUBSCRIPTION_ID': 'sub', 'AZURE_RESOURCE_GROUP': 'group'}), patch.object(boxes, 'az', return_value={'value': [], 'nextLink': 'https://example.invalid/'}):
            with self.assertRaises(RuntimeError):
                boxes.inventory()

    def test_cli_error_never_exposes_output_or_arguments(self):
        with patch.object(boxes.subprocess, 'run') as run:
            run.return_value.returncode = 1
            run.return_value.stdout = 'PRIVATE RESPONSE'
            run.return_value.stderr = 'PRIVATE ERROR'
            with self.assertRaisesRegex(RuntimeError, '^Azure operation failed: vm create$'):
                boxes.az('vm', 'create', '--admin-password', 'synthetic-placeholder')

    def test_up_both_operating_systems_and_failed_guest_cleanup(self):
        for os_name, fail_guest in [('windows-2025', False), ('windows-2022', False), ('ubuntu-24.04', False), ('windows-2025', True)]:
            with self.subTest(os=os_name, fail_guest=fail_guest), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'keys').mkdir()
                (root / 'keys/agent-ssh.pub').write_text('ssh-ed25519 AAAA synthetic-test\n')
                (root / 'scripts').mkdir()
                (root / 'scripts/test-boxes-windows.ps1').write_text('__PUBLIC_KEY__')
                vm = resource('ygbox-test-123', box='ygbox-test-123')
                disk = resource('ygbox-test-123-os', boxes.DISK_TYPE, box='ygbox-test-123')
                calls = []

                def fake_az(*args, timeout=None):
                    calls.append(args)
                    if args[:3] == ('network', 'public-ip', 'show'):
                        return {'ipAddress': '192.0.2.1'}
                    if args[:3] == ('vm', 'run-command', 'invoke'):
                        script = args[args.index('--scripts') + 1]
                        if 'YG_SETUP_STARTED' in script:
                            return {'value': [{'message': 'YG_SETUP_STARTED'}]}
                        tail = 'YG_FAIL host keys' if fail_guest else 'YG_SSH_READY'
                        return {'value': [{'message': '[+0s] start\n[+4s] host keys\nC:\\Users\\x 10.1.2.3\n' + tail}]}
                    if args[:2] == ('vm', 'get-instance-view'):
                        return {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Ready'}]}}}
                    return {}

                old = os.getcwd()
                try:
                    os.chdir(root)
                    out = io.StringIO()
                    with patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'AZURE_RESOURCE_GROUP': 'mock', 'GITHUB_OUTPUT': str(root/'output'), 'GITHUB_STEP_SUMMARY': str(root/'summary')}), patch.object(boxes, 'login'), patch.object(boxes, 'az', side_effect=fake_az), patch.object(boxes, 'inventory', side_effect=[[], [vm, disk], [vm, disk]]), patch.object(boxes.time, 'sleep'), contextlib.redirect_stdout(out):
                        inputs = {'label': 'test', 'os': os_name, 'allow_cidr': '8.8.8.8/32'}
                        if fail_guest:
                            with self.assertRaisesRegex(RuntimeError, 'Windows SSH setup failed at host keys'):
                                boxes.up(inputs)
                            self.assertFalse((root/'output').exists())
                            self.assertEqual([c[-1] for c in calls if c[:2] == ('resource', 'delete')], [vm['id'], disk['id']])
                        else:
                            boxes.up(inputs)
                            self.assertEqual(set(line.split('=')[0] for line in (root/'output').read_text().splitlines()), {'name', 'public_ip', 'os', 'expires'})
                            vm_call = next(c for c in calls if c[:2] == ('vm', 'create'))
                            self.assertEqual('--admin-password' in vm_call, os_name.startswith('windows-'))
                            self.assertIn(boxes.IMAGES[os_name], vm_call)
                            self.assertIn('Premium_LRS', vm_call)
                            self.assertEqual(any(c[:3] == ('vm', 'run-command', 'invoke') for c in calls), os_name.startswith('windows-'))
                            if os_name.startswith('windows-'):
                                launch = next(c for c in calls if c[:3] == ('vm', 'run-command', 'invoke'))
                                payload = launch[launch.index('--scripts') + 1].split("FromBase64String('")[1].split("'")[0]
                                self.assertIn('ssh-ed25519 AAAA', base64.b64decode(payload).decode())
                                self.assertNotIn('synthetic-test', base64.b64decode(payload).decode())
                                self.assertIn('guest: [+4s] host keys', out.getvalue())
                            self.assertEqual('--ssh-key-values' in vm_call, os_name == 'ubuntu-24.04')
                            rules = [c for c in calls if c[:4] == ('network', 'nsg', 'rule', 'create')]
                            self.assertEqual(len(rules), 3)
                            self.assertIn('Deny', rules[0])
                            self.assertIn('22', rules[1])
                            self.assertIn('51600-51699', rules[2])
                        self.assertNotIn('10.1.2.3', out.getvalue())
                        self.assertNotIn('Users', out.getvalue())
                finally:
                    os.chdir(old)

    def test_guest_agent_wait_and_status_keep_only_fixed_words(self):
        views = [{'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Not Ready'}]}}},
                 {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Ready'}]},
                                   'extensions': [{'name': 'RunCommandWindows', 'statuses': [
                                       {'code': 'ProvisioningState/transitioning', 'message': 'secret 10.0.0.4 output'}]}]}}]
        with patch.object(boxes, 'az', side_effect=views + views[1:]), patch.object(boxes.time, 'sleep') as sleep:
            boxes.wait_guest_agent([], 'box')
            self.assertEqual(sleep.call_count, 1)
            agent, exts = boxes.guest_status([], 'box')
        self.assertEqual(agent, 'Ready')
        self.assertEqual(exts, 'RunCommandWindows=ProvisioningState/transitioning')
        never = {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Not Ready'}]}}}
        with patch.object(boxes, 'az', return_value=never), patch.object(boxes.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Guest agent not ready: Not Ready'):
                boxes.wait_guest_agent([], 'box', limit=-1)

    def test_guest_setup_stuck_names_last_step_and_agent_wait_survives_one_error(self):
        polls = iter(['[+0s] start\n[+2s] openssh capability'] * 5)

        def fake_az(*args, timeout=None):
            if args[:2] == ('vm', 'get-instance-view'):
                return {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Ready'}]}}}
            script = args[args.index('--scripts') + 1]
            return {'value': [{'message': 'YG_SETUP_STARTED' if 'YG_SETUP_STARTED' in script else next(polls)}]}
        out = io.StringIO()
        with patch.object(boxes, 'az', side_effect=fake_az), patch.object(boxes.time, 'sleep'), contextlib.redirect_stdout(out):
            with self.assertRaisesRegex(RuntimeError, 'stuck after: \\[\\+2s\\] openssh capability'):
                boxes.guest_ssh_setup([], 'box', 'script', limit=-1)
        self.assertIn('guest status: agent=Ready', out.getvalue())
        calls = iter([RuntimeError('Azure operation failed: vm get-instance-view'),
                      {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': 'Ready'}]}}}])

        def flaky(*args, timeout=None):
            value = next(calls)
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(boxes, 'az', side_effect=flaky), patch.object(boxes.time, 'sleep'):
            boxes.wait_guest_agent([], 'box')

    def test_clones_regenerate_ssh_host_keys_per_vm(self):
        script = (Path(__file__).resolve().parents[1] / 'scripts/test-boxes-windows.ps1').read_text()
        task = script.split("@'\n$ErrorActionPreference")[1].split("'@ | Set-Content -Path 'C:\\yg\\ssh-hostkeys.ps1'")[0]
        self.assertIn('Win32_ComputerSystemProduct', task)
        self.assertIn("Remove-Item 'C:\\ProgramData\\ssh\\ssh_host_*' -Force", task)
        self.assertNotIn('finally', task)
        self.assertIn('Stop-Service sshd\n', task)
        self.assertNotIn('SilentlyContinue', task)
        self.assertIn("if ((Test-Path $marker) -and (Get-Content $marker -Raw).Trim() -eq $vm) {\n        Start-Service sshd\n    } else {\n        exit 1\n    }", task)
        self.assertEqual(task.count('Start-Service sshd'), 1)
        self.assertIn('} catch {\n    exit 1\n}', task)
        self.assertLess(task.index('Set-Content -Path $marker -Value $vm'), task.index('Start-Service sshd'))
        self.assertIn('-StartupType Manual', script)
        self.assertNotIn('-StartupType Automatic', script)
        self.assertIn('New-ScheduledTaskTrigger -AtStartup', script)

    def test_default_os_is_windows_2025_and_unknown_os_refused(self):
        workflow = (Path(__file__).parents[1] / '.github/workflows/box-up.yml').read_text()
        self.assertIn('default: windows-2025', workflow)
        self.assertIn('timeout-minutes: 50', workflow)
        with tempfile.TemporaryDirectory() as directory:
            old = os.getcwd()
            try:
                os.chdir(directory)
                Path('keys').mkdir()
                Path('keys/agent-ssh.pub').write_text('ssh-ed25519 AAAA synthetic-test\n')
                with patch.object(boxes, 'login') as login, self.assertRaisesRegex(boxes.ValidationError, 'Invalid os'), contextlib.redirect_stdout(io.StringIO()):
                    boxes.up({'label': 'test', 'os': 'windows-2019', 'allow_cidr': '8.8.8.8/32'})
                login.assert_not_called()
            finally:
                os.chdir(old)

    def test_stuck_cli_call_times_out_with_its_step_named(self):
        with patch.object(boxes.subprocess, 'run', side_effect=boxes.subprocess.TimeoutExpired('az', 1)) as run:
            with self.assertRaisesRegex(RuntimeError, r'^Azure operation failed: vm create \[Timeout\]$'):
                boxes.az('vm', 'create', '--admin-password', 'synthetic-placeholder')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['timeout'], boxes.TIMEOUTS[('vm', 'create')])

    def test_gallery_timeouts_apply_to_the_correct_operations(self):
        for operation, limit in [(('sig', 'create'), 900),
                                 (('sig', 'image-definition', 'create'), 900),
                                 (('sig', 'image-definition', 'show'), 900),
                                 (('sig', 'image-version', 'create'), 3600),
                                 (('sig', 'image-version', 'list'), 300)]:
            with self.subTest(operation=operation), patch.object(boxes.subprocess, 'run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = '{}'
                boxes.az(*operation)
                self.assertEqual(run.call_args.kwargs['timeout'], limit)

    def test_mask_escapes_workflow_command_characters(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            boxes.mask('fake%\n::error::example\r')
        self.assertEqual(output.getvalue(), '::add-mask::fake%25%0A::error::example%0D\n')


if __name__ == '__main__':
    unittest.main()
