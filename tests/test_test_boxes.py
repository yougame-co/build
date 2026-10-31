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


def resource(name, kind=boxes.VM_TYPE, **tags):
    return {'name': name, 'id': '/mock/' + name, 'type': kind,
            'createdTime': (NOW - dt.timedelta(hours=1)).isoformat(),
            'tags': {'owner': 'agent', 'expires': (NOW + dt.timedelta(hours=1)).isoformat(), **tags}}


class LifecycleTests(unittest.TestCase):
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

                def fake_az(*args):
                    calls.append(args)
                    if args[:3] == ('network', 'public-ip', 'show'):
                        return {'ipAddress': '192.0.2.1'}
                    if args[:3] == ('vm', 'run-command', 'invoke'):
                        return {'value': [{'message': 'guest failed' if fail_guest else 'YG_SSH_READY'}]}
                    return {}

                old = os.getcwd()
                try:
                    os.chdir(root)
                    with patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'AZURE_RESOURCE_GROUP': 'mock', 'GITHUB_OUTPUT': str(root/'output'), 'GITHUB_STEP_SUMMARY': str(root/'summary')}), patch.object(boxes, 'login'), patch.object(boxes, 'az', side_effect=fake_az), patch.object(boxes, 'inventory', side_effect=[[], [vm, disk], [vm, disk]]), contextlib.redirect_stdout(io.StringIO()):
                        inputs = {'label': 'test', 'os': os_name, 'allow_cidr': '8.8.8.8/32'}
                        if fail_guest:
                            with self.assertRaisesRegex(RuntimeError, 'Windows SSH setup failed'):
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
                            self.assertEqual('--ssh-key-values' in vm_call, os_name == 'ubuntu-24.04')
                            rules = [c for c in calls if c[:4] == ('network', 'nsg', 'rule', 'create')]
                            self.assertEqual(len(rules), 3)
                            self.assertIn('Deny', rules[0])
                            self.assertIn('22', rules[1])
                            self.assertIn('51600-51699', rules[2])
                finally:
                    os.chdir(old)

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

    def test_mask_escapes_workflow_command_characters(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            boxes.mask('fake%\n::error::example\r')
        self.assertEqual(output.getvalue(), '::add-mask::fake%25%0A::error::example%0D\n')


if __name__ == '__main__':
    unittest.main()
