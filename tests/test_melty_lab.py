"""Offline only: every az process and the OIDC token request are replaced."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('melty_lab', REPO / 'scripts/melty-lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
NAME = 'melty-lab-abcdef'
RG = 'yougame-test-boxes'
NOW = dt.datetime(2026, 10, 31, 19, 0, tzinfo=lab.UTC)
EXPIRES = '2026-11-01T02:00Z'
TOKEN = 'oidc-token-do-not-print'


class FakeAz:
    """subprocess.run substitute: record complete argv and simulate a small RG."""
    def __init__(self):
        self.calls, self.resources = [], []
        self.identity = None
        self.harden = 'MELTY_READY\n'
        self.agent_ready_after = 0
        self.password_seen = None

    def add(self, kind, name, tags=None):
        item = dict(type=kind, name=name, tags=tags or {},
                    id=f'/subscriptions/offline/resourceGroups/{RG}/providers/{kind}/{name}')
        self.resources.append(item)
        return item

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        assert argv[0] == 'az'
        assert kwargs['stdin'] is subprocess.DEVNULL
        assert kwargs['timeout'] > 0
        assert kwargs['env']['AZURE_CORE_COLLECT_TELEMETRY'] == 'false'
        assert kwargs['env']['AZURE_LOGGING_ENABLE_LOG_FILE'] == 'false'
        assert kwargs['env']['AZURE_EXTENSION_USE_DYNAMIC_INSTALL'] == 'no'
        a = argv[1:]
        def val(key):
            return a[a.index(key) + 1]
        def tags():
            result = {}
            if '--tags' in a:
                for value in a[a.index('--tags') + 1:]:
                    if value.startswith('--'):
                        break
                    key, value = value.split('=', 1)
                    result[key] = value
            return result
        response = {}
        if a[:2] == ['resource', 'list']:
            response = self.resources
        elif a[:3] == ['network', 'nsg', 'create']:
            self.add('Microsoft.Network/networkSecurityGroups', val('--name'), tags())
        elif a[:3] in [['network', kind, 'create'] for kind in ('vnet', 'nic', 'public-ip')]:
            kind = dict(vnet='virtualNetworks', nic='networkInterfaces', **{'public-ip': 'publicIPAddresses'})[a[1]]
            self.add('Microsoft.Network/' + kind, val('--name'), tags())
        elif a[:2] == ['vm', 'create']:
            path = Path(val('--admin-password')[1:])
            self.password_seen = (path.read_text(), stat.S_IMODE(path.stat().st_mode), path)
            self.add('Microsoft.Compute/virtualMachines', val('--name'), tags())
            self.add('Microsoft.Compute/disks', val('--os-disk-name'))
        elif a[:2] == ['vm', 'show']:
            response = {'identity': self.identity}
        elif a[:2] == ['vm', 'get-instance-view']:
            self.agent_ready_after -= 1
            status = 'Ready' if self.agent_ready_after < 0 else 'Not Ready'
            response = {'instanceView': {'vmAgent': {'statuses': [{'displayStatus': status}]}}}
        elif a[:2] == ['vm', 'auto-shutdown']:
            self.add('Microsoft.DevTestLab/schedules', 'shutdown-computevm-' + val('--name'))
        elif a[:2] == ['resource', 'tag']:
            for r in self.resources:
                if r['name'] == val('--name') and r['type'].lower() == val('--resource-type').lower():
                    r['tags'] = tags()
        elif a[:2] == ['resource', 'show']:
            response = {'properties': {'targetResourceId':
                        f'/subscriptions/offline/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{NAME}'}}
        elif a[:2] == ['resource', 'delete']:
            self.resources = [r for r in self.resources if r['id'] != val('--ids')]
        elif a[:3] == ['vm', 'run-command', 'invoke']:
            return subprocess.CompletedProcess(argv, 0, self.harden, '')
        return subprocess.CompletedProcess(argv, 0, json.dumps(response), '')


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fake = FakeAz()
        self.az = lab.Az(self.fake)
        self.requests = []

    def opener(self, request, timeout):
        self.requests.append(request)
        return FakeResponse(json.dumps({'value': TOKEN}).encode())

    def main(self, command, inputs):
        event, out_file, summary = self.root / 'event.json', self.root / 'out', self.root / 'summary'
        event.write_text(json.dumps({'inputs': inputs}))
        env = dict(GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(out_file), GITHUB_STEP_SUMMARY=str(summary),
                   AZURE_RESOURCE_GROUP=RG, AZURE_CLIENT_ID='client', AZURE_TENANT_ID='tenant',
                   AZURE_SUBSCRIPTION_ID='sub', ACTIONS_ID_TOKEN_REQUEST_TOKEN='bearer-do-not-print',
                   ACTIONS_ID_TOKEN_REQUEST_URL='https://token.example/x?a=1')
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env), patch.object(lab.secrets, 'token_hex', return_value='abcdef'), \
                patch.object(lab, 'login', lambda az: real_login(az, self.opener)), \
                patch.object(lab.time, 'sleep'), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                lab.main([command], az=self.az, now=NOW)
            finally:
                self.last_out = out.getvalue()
        written = out_file.read_text() if out_file.exists() else ''
        return out.getvalue(), err.getvalue(), written

    def up(self, **extra):
        return self.main('up', dict(allow_cidr='8.8.8.8/32', expires=EXPIRES, **extra))

    def test_public_cidr(self):
        self.assertEqual(lab.valid_cidr('8.8.8.8/32'), '8.8.8.8/32')

    def test_cidr_refusals(self):
        for cidr in ['8.8.8.8', '8.8.8.0/24', '10.0.0.1/32', '172.16.0.1/32',
                     '192.168.1.1/32', '127.0.0.1/32', '169.254.1.1/32', '100.64.0.1/32',
                     '100.127.255.254/32', '0.0.0.0/32', '224.0.0.1/32', '::1/128', '::ffff:8.8.8.8/128',
                     '2001:4860:4860::8888/128', '8.8.8.8/32,1.1.1.1/32', 'bad', None]:
            with self.subTest(cidr=cidr):
                with self.assertRaises(lab.ValidationError) as error:
                    lab.valid_cidr(cidr)
                self.assertNotIn(str(cidr), str(error.exception))

    def test_expires_window(self):
        self.assertEqual(lab.valid_expires('2026-10-31T19:30Z', NOW), NOW + dt.timedelta(minutes=30))
        self.assertEqual(lab.valid_expires('2026-11-01T03:00:00Z', NOW), NOW + dt.timedelta(hours=8))
        for value in ('2026-10-31T19:29Z', '2026-11-01T03:01Z', '2026-10-31T18:00Z', '2026-11-01T02:00',
                      '2026-11-01T02:00:30Z', '2026-11-01 02:00Z', '2026-13-01T02:00Z', 'tomorrow', None):
            with self.subTest(value=value):
                with self.assertRaises(lab.ValidationError):
                    lab.valid_expires(value, NOW)

    def test_password_classes(self):
        for _ in range(20):
            value = lab.password()
            self.assertGreaterEqual(len(value), 24)
            for chars in (lab.string.ascii_uppercase, lab.string.ascii_lowercase, lab.string.digits, '!#$%&*+-=?_'):
                self.assertTrue(set(chars) & set(value))

    def test_up_password_never_kept_printed_or_in_argv(self):
        out, err, written = self.up()
        secret, mode, path = self.fake.password_seen
        self.assertEqual(mode, 0o600)
        self.assertFalse(path.exists())
        self.assertGreaterEqual(len(secret), 24)
        escaped = '::add-mask::' + secret.replace('%', '%25')
        visible = out.replace(escaped, '')
        self.assertNotIn(secret, visible + err + written)
        self.assertIn(escaped + '\n', out)
        self.assertLess(out.index(escaped), out.index('vm create'))
        for argv, _ in self.fake.calls:
            self.assertTrue(all(secret not in arg for arg in argv))
        create = next(c for c, _ in self.fake.calls if c[1:3] == ['vm', 'create'])
        self.assertEqual(create[create.index('--admin-username') + 1], 'meltyadmin')
        self.assertEqual(create[create.index('--image') + 1], lab.IMAGE)
        self.assertEqual(create[create.index('--size') + 1], 'Standard_D4s_v6')
        self.assertNotIn('--assign-identity', create)

    def test_up_reports_only_name_expiry_and_group(self):
        out, err, written = self.up()
        self.assertEqual(written, f'name={NAME}\nexpires=2026-11-01T02:00:00Z\nresource_group={RG}\n')
        for hidden in ('8.8.8.8', TOKEN, 'bearer-do-not-print', 'sub', 'tenant', 'client'):
            visible = '\n'.join(l for l in out.splitlines() if not l.startswith('::add-mask::'))
            self.assertNotIn(hidden, visible + err + written, hidden)
        self.assertIn('::add-mask::8.8.8.8/32', out)
        self.assertIn('::add-mask::8.8.8.8\n', out)
        self.assertIn('::add-mask::' + TOKEN, out)

    def test_up_tags_and_shutdown_at_expiry(self):
        self.up()
        for r in self.fake.resources:
            self.assertEqual(r['tags'], {'owner': 'agent', 'box': NAME, 'purpose': 'melty-lab',
                                         'created': '2026-10-31T19:00:00Z', 'expires': '2026-11-01T02:00:00Z'})
        shutdown = next(c for c, _ in self.fake.calls if c[1:3] == ['vm', 'auto-shutdown'])
        self.assertEqual(shutdown[shutdown.index('--time') + 1], '0200')
        scripts = [c[c.index('--scripts') + 1] for c, _ in self.fake.calls if '--scripts' in c]
        self.assertEqual(scripts, [lab.HARDEN])

    def test_login_uses_oidc_federated_token(self):
        self.up()
        request = self.requests[0]
        self.assertEqual(request.get_header('Authorization'), 'Bearer bearer-do-not-print')
        self.assertIn('audience=api%3A%2F%2FAzureADTokenExchange', request.full_url)
        logins = [c for c, _ in self.fake.calls if c[1] == 'login']
        self.assertEqual(len(logins), 1)
        self.assertIn('--federated-token', logins[0])
        self.assertEqual(self.fake.calls[0][0][1], 'login')

    def test_network_and_hardening(self):
        with contextlib.redirect_stdout(io.StringIO()):
            lab.provision(self.az, dict(allow_cidr='8.8.8.8/32', expires=EXPIRES), RG, NAME, NOW, sleep=lambda s: None)
        calls = [c for c, _ in self.fake.calls]
        rules = [c for c in calls if c[1:5] == ['network', 'nsg', 'rule', 'create']]
        self.assertEqual(len(rules), 6)
        inbound = [c for c in rules if 'Inbound' in c and 'Allow' in c]
        self.assertEqual(len(inbound), 1)
        self.assertEqual(inbound[0][inbound[0].index('--source-address-prefixes') + 1], '8.8.8.8/32')
        self.assertEqual(inbound[0][inbound[0].index('--destination-port-ranges') + 1], '3389')
        dests = {c[c.index('--destination-address-prefixes') + 1] for c in rules if 'Outbound' in c}
        self.assertEqual(dests, {'VirtualNetwork', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'})
        vnet = next(c for c in calls if c[1:4] == ['network', 'vnet', 'create'])
        self.assertIn('10.43.0.0/24', vnet)
        self.assertFalse(any('peering' in c or 'private-endpoint' in c or 'extension' in c for c in calls))
        self.assertTrue(any(c[1:3] == ['vm', 'boot-diagnostics'] for c in calls))
        for value in ('fDisableClip', 'fDisableCdm', 'fDisableCpm', 'fDisableCcm', 'fDisableLPT',
                      'fDisablePNPRedir', 'fEnableSmartCard', 'fDisableCameraRedir', 'fDisableWebAuthn'):
            self.assertIn(value, lab.HARDEN)

    def test_waits_for_guest_agent_before_hardening(self):
        self.fake.agent_ready_after = 2
        self.up()
        kinds = [c[1:3] for c, _ in self.fake.calls]
        views = [i for i, k in enumerate(kinds) if k == ['vm', 'get-instance-view']]
        self.assertEqual(len(views), 3)
        self.assertLess(views[-1], kinds.index(['vm', 'run-command']))

    def test_identity_and_failed_hardening_cleanup(self):
        for identity, harden in [({'type': 'SystemAssigned'}, 'MELTY_READY\n'), (None, 'not ready\n')]:
            with self.subTest(identity=identity, harden=harden):
                self.fake.identity, self.fake.harden = identity, harden
                with self.assertRaises(lab.ValidationError):
                    self.up()
                self.assertEqual(self.fake.resources, [])
                self.assertFalse(self.fake.password_seen[2].exists())

    def test_collision_never_deletes(self):
        self.fake.add('Microsoft.Network/networkSecurityGroups', NAME + '-nsg', {'owner': 'agent', 'box': NAME})
        with self.assertRaises(lab.ValidationError):
            self.up()
        self.assertEqual(len(self.fake.resources), 1)
        self.assertFalse(any('delete' in c for c, _ in self.fake.calls))

    def test_bad_input_no_azure_contact(self):
        for inputs in [dict(allow_cidr='10.0.0.1/32', expires=EXPIRES), dict(allow_cidr='8.8.8.8/32', expires='bad'),
                       dict(allow_cidr='8.8.8.8/32', expires=EXPIRES, size='Standard_NC96ads_A100_v4')]:
            with self.subTest(inputs=inputs):
                with self.assertRaises(lab.ValidationError):
                    self.main('up', inputs)
        for name in ('../x', 'ygbox-a-1', 'melty-lab-abcdeg', None):
            with self.assertRaises(lab.ValidationError):
                self.main('down', {'name': name})
        with self.assertRaises(lab.ValidationError):
            lab.main(['plan'], az=self.az)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.requests, [])

    def test_down_command(self):
        self.up()
        out, _, written = self.main('down', {'name': NAME})
        self.assertEqual(self.fake.resources, [])
        self.assertEqual(written.splitlines()[-2:], [f'name={NAME}', 'deleted=7'])

    def test_down_all_removes_only_melty_boxes(self):
        self.up()
        other = self.fake.add('Microsoft.Compute/virtualMachines', 'ygbox-x-1', {'owner': 'agent', 'box': 'ygbox-x-1'})
        luis = self.fake.add('Microsoft.Compute/virtualMachines', 'melty-lab-123456', {'owner': 'luis', 'box': 'melty-lab-123456',
                                                                                       'purpose': 'melty-lab'})
        _, _, written = self.main('down', {'name': 'all'})
        self.assertEqual(self.fake.resources, [other, luis])
        self.assertIn(f'name={NAME}\ndeleted=7', written)

    def test_optional_steps_do_not_fail_the_box(self):
        class NoDevTestLab(FakeAz):
            def __call__(self, argv, **kwargs):
                if argv[1:3] in (['vm', 'auto-shutdown'], ['vm', 'boot-diagnostics']):
                    self.calls.append((argv, kwargs))
                    return subprocess.CompletedProcess(argv, 1, '', 'ERROR: (MissingSubscriptionRegistration) no')
                return super().__call__(argv, **kwargs)
        self.fake = NoDevTestLab()
        self.az = lab.Az(self.fake)
        out, _, written = self.up()
        self.assertIn('note: auto-shutdown unavailable (MissingSubscriptionRegistration)', out)
        self.assertIn('note: boot diagnostics off unavailable', out)
        self.assertIn(f'name={NAME}', written)
        self.assertFalse(any(c[1:3] == ['resource', 'tag'] and 'Microsoft.DevTestLab/schedules' in c for c, _ in self.fake.calls))

    def test_failure_prints_original_error_then_cleans_up(self):
        self.fake.identity = {'type': 'SystemAssigned'}
        with self.assertRaises(lab.ValidationError):
            self.up()
        self.assertIn('failed: VM unexpectedly has an identity', self.last_out)
        self.assertLess(self.last_out.index('name: ' + NAME), self.last_out.index('failed:'))

    def test_down_order_and_recovery(self):
        tags = {'owner': 'agent', 'box': NAME}
        for kind, suffix, owned in [('Microsoft.Network/virtualNetworks', '-vnet', True),
                                    ('Microsoft.Compute/disks', '-os', False),
                                    ('Microsoft.Network/networkInterfaces', '-nic', True),
                                    ('Microsoft.Network/publicIPAddresses', '-ip', True),
                                    ('Microsoft.Network/networkSecurityGroups', '-nsg', True),
                                    ('Microsoft.Compute/virtualMachines', '', True)]:
            self.fake.add(kind, NAME + suffix, tags if owned else {})
        self.fake.add('Microsoft.DevTestLab/schedules', 'shutdown-computevm-' + NAME)
        foreign = self.fake.add('Microsoft.Compute/disks', NAME + '-other', {'owner': 'luis', 'box': NAME})
        lab.down(self.az, NAME, RG)
        deleted = [c[c.index('--ids') + 1].split('/')[-1] for c, _ in self.fake.calls if c[1:3] == ['resource', 'delete']]
        self.assertEqual(deleted, [NAME, NAME + '-nic', NAME + '-os', NAME + '-ip', NAME + '-nsg',
                                   NAME + '-vnet', 'shutdown-computevm-' + NAME])
        self.assertEqual(self.fake.resources, [foreign])

    def test_down_does_not_adopt_without_anchor(self):
        self.fake.add('Microsoft.Compute/disks', NAME + '-os')
        lab.down(self.az, NAME, RG)
        self.assertEqual(len(self.fake.resources), 1)

    def test_delete_retry_preserves_order(self):
        class RetryFake(FakeAz):
            failed = False
            def __call__(self, argv, **kwargs):
                if argv[1:3] == ['resource', 'delete'] and not self.failed:
                    self.failed = True
                    self.calls.append((argv, kwargs))
                    return subprocess.CompletedProcess(argv, 1, '', 'ERROR: (Conflict) still busy')
                return super().__call__(argv, **kwargs)
        fake = RetryFake()
        for kind, suffix in [('Microsoft.Compute/virtualMachines', ''),
                             ('Microsoft.Network/networkInterfaces', '-nic')]:
            fake.add(kind, NAME + suffix, {'owner': 'agent', 'box': NAME})
        with patch.object(lab.time, 'sleep') as sleep:
            lab.down(lab.Az(fake), NAME, RG)
        sleep.assert_called_once_with(10)
        deleted = [c[c.index('--ids') + 1].split('/')[-1] for c, _ in fake.calls if c[1:3] == ['resource', 'delete']]
        self.assertEqual(deleted, [NAME, NAME, NAME + '-nic'])

    def test_down_verifies_zero(self):
        class StuckFake(FakeAz):
            def __call__(self, argv, **kwargs):
                if argv[1:3] == ['resource', 'delete']:
                    return subprocess.CompletedProcess(argv, 0, '{}', '')
                return super().__call__(argv, **kwargs)
        stuck = StuckFake()
        stuck.add('Microsoft.Compute/virtualMachines', NAME, {'owner': 'agent', 'box': NAME})
        with patch.object(lab.time, 'sleep') as sleep, self.assertRaises(lab.ValidationError):
            lab.down(lab.Az(stuck), NAME, RG)
        self.assertEqual(sleep.call_count, 3)

    def test_error_masking_secret_and_guest_output(self):
        secret = 'A-secret-do-not-print-123!'
        def fail(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 1, '', f'ERROR: (Denied) from 8.8.8.8/32 and 2001:4860::8888 sub 0f0e0d0c-1111-2222-3333-444455556666 {secret}\ntraceback')
        az = lab.Az(fail)
        az.secret = secret
        with self.assertRaises(lab.AzureError) as error:
            az('vm', 'create')
        message = str(error.exception)
        self.assertIn('Denied', message)
        for hidden in ('8.8.8.8', '2001:4860', '0f0e0d0c', secret, 'traceback'):
            self.assertNotIn(hidden, message)
        with self.assertRaises(lab.AzureError) as error:
            az('vm', 'run-command', 'invoke', raw=True)
        self.assertNotIn('from', str(error.exception))

    def test_workflows_dispatch_only_oidc_pinned(self):
        for name, command in (('melty-up.yml', 'up'), ('melty-down.yml', 'down')):
            text = (REPO / '.github/workflows' / name).read_text()
            with self.subTest(workflow=name):
                on = text.split('\non:\n', 1)[1].split('\n\n', 1)[0]
                self.assertIn('workflow_dispatch:', on)
                for trigger in ('push:', 'pull_request', 'schedule:', 'workflow_run'):
                    self.assertNotIn(trigger, on)
                self.assertIn('environment: test-boxes', text)
                self.assertIn('permissions:\n  contents: read\n  id-token: write\n', text)
                self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683', text)
                self.assertIn('persist-credentials: false', text)
                self.assertIn('python3 scripts/melty-lab.py ' + command, text)
                self.assertNotIn('secrets.', text)
                self.assertNotIn('inputs.allow_cidr', text)
        up = (REPO / '.github/workflows/melty-up.yml').read_text()
        self.assertLess(up.index('::add-mask::'), up.index('actions/checkout@'))


real_login = lab.login


if __name__ == '__main__':
    unittest.main()
