#!/usr/bin/env python3
"""Melty lab: one disposable Windows Server desktop for a hands-on launcher session, reached over RDP.

Runs only in GitHub Actions (OIDC, environment test-boxes). The guest is treated as hostile: its own VNet, RDP only
from one public /32, no private-range egress, no managed identity, server-side RDP redirection (clipboard included)
off. The admin password is random, lives in memory and one tmpfs file for the single vm create call, and is never
printed or kept: the owner sets their own with the portal's Reset password. The public log shows only the box name,
expiry and resource group; the portal shows the address.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

UTC = dt.timezone.utc
ADMIN = 'meltyadmin'
VM, DISK, SCHEDULE = ('microsoft.compute/virtualmachines', 'microsoft.compute/disks',
                      'microsoft.devtestlab/schedules')
# Windows 11 images need eligible client licences on Azure; Server 2025 Desktop Experience is licensed pay-as-you-go.
# The same image the test boxes boot (box run 41226635504).
IMAGE = 'MicrosoftWindowsServer:WindowsServer:2025-datacenter-g2:latest'
SIZES = ('Standard_D4s_v6', 'Standard_D2s_v6', 'Standard_D4as_v7', 'Standard_D8s_v6')
TAIL = ['--only-show-errors', '--output', 'json']
TIMEOUTS = {('vm', 'create'): 900, ('vm', 'run-command'): 900}
MIN_LIFE, MAX_LIFE = dt.timedelta(minutes=30), dt.timedelta(hours=8)
STARTED = time.monotonic()


class ValidationError(Exception):
    pass


def masked(text):
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b', '<ip>', str(text))
    text = re.sub(r'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])', '<ip>', text)
    text = re.sub(r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '<guid>', text)
    return ''.join(c if c.isprintable() else ' ' for c in text)[:400]


def mask(value):
    # Escape workflow-command metacharacters, including hostile dispatch input.
    value = str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::add-mask::' + value, flush=True)


def step(name):
    # Fixed step names only, so a slow step is visible in the public log.
    print('[+%ds] %s' % (time.monotonic() - STARTED, name), flush=True)


class AzureError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(masked(code + ': ' + message))


class Az:
    def __init__(self, runner=subprocess.run):
        self.runner, self.secret = runner, ''

    def __call__(self, *args, raw=False):
        tail = ['--only-show-errors', '--query',
                "value[?code=='ComponentStatus/StdOut/succeeded'].message | [0]",
                '--output', 'tsv'] if raw else TAIL
        env = dict(os.environ, AZURE_CORE_COLLECT_TELEMETRY='false',
                   AZURE_LOGGING_ENABLE_LOG_FILE='false', AZURE_EXTENSION_USE_DYNAMIC_INSTALL='no')
        limit = TIMEOUTS.get(tuple(args[:2]), 300)
        for attempt in range(3):
            try:
                r = self.runner(['az', *args, *tail], capture_output=True, text=True,
                                check=False, env=env, stdin=subprocess.DEVNULL, timeout=limit)
            except subprocess.TimeoutExpired:
                raise AzureError('Timeout', ' '.join(args[:2])) from None
            # az 2.91 import-deadlock crash with its telemetry thread: retry exactly that (box run 41177256736).
            if not (r.returncode and '_DeadlockError' in (r.stderr or '')):
                break
        if r.returncode:
            error = (r.stderr or '').replace(self.secret, '<password>') if self.secret else (r.stderr or '')
            match = re.search(r'(?:ERROR:\s*)?\(([A-Za-z][A-Za-z0-9_.]{0,63})\)\s*([^\r\n]*)', error)
            code, message = match.groups() if match else ('CliFailure', 'Azure CLI failed; details withheld')
            if raw:
                message = 'Run command failed; guest output withheld'
            raise AzureError(code, ' '.join(args[:2]) + ': ' + masked(message))
        if len(r.stdout or '') > (4096 if raw else 4 * 1024 * 1024):
            raise ValidationError('Azure response too large')
        return r.stdout if raw else json.loads(r.stdout or 'null')


def login(az, opener=urllib.request.urlopen):
    bearer = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    mask(bearer)
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    url += ('&' if '?' in url else '?') + urllib.parse.urlencode({'audience': 'api://AzureADTokenExchange'})
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + bearer})
    with opener(request, timeout=30) as response:
        token = json.load(response)['value']
    mask(token)
    az('login', '--service-principal', '-u', os.environ['AZURE_CLIENT_ID'],
       '-t', os.environ['AZURE_TENANT_ID'], '--federated-token', token, '--allow-no-subscriptions')
    az('account', 'set', '--subscription', os.environ['AZURE_SUBSCRIPTION_ID'])


def name_ok(name):
    if not re.fullmatch(r'melty-lab-[0-9a-f]{6}', str(name)):
        raise ValidationError('Invalid box name')
    return name


def valid_cidr(value):
    try:
        if not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}/32', str(value)):
            raise ValueError()
        net = ipaddress.ip_network(value, strict=True)
        if net.version != 4 or net.prefixlen != 32 or not net.network_address.is_global or net.network_address.is_multicast:
            raise ValueError()
    except ValueError:
        raise ValidationError('allow_cidr must be a single public IPv4 /32') from None
    return str(net)


def valid_expires(value, now):
    # An absolute UTC minute: the auto-shutdown schedule has minute precision.
    m = re.fullmatch(r'(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::00)?Z', str(value))
    try:
        if not m:
            raise ValueError()
        end = dt.datetime.strptime('%sT%s:%s' % m.groups(), '%Y-%m-%dT%H:%M').replace(tzinfo=UTC)
    except ValueError:
        raise ValidationError('expires must be a UTC time like 2026-11-01T02:00Z') from None
    if not now + MIN_LIFE <= end <= now + MAX_LIFE:
        raise ValidationError('expires must be 30 minutes to 8 hours from now')
    return end


def valid_size(value):
    if value not in SIZES:
        raise ValidationError('size must be one of ' + ', '.join(SIZES))
    return value


def stamp(t):
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def password():
    classes = [string.ascii_uppercase, string.ascii_lowercase, string.digits, '!#$%&*+-=?_']
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(''.join(classes)) for _ in range(28)]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


def secret_file(value):
    # tmpfs where the runner has it (memory only), mode 600, exclusive; the caller unlinks it right after use.
    shm = Path('/dev/shm')
    fd, path = tempfile.mkstemp(prefix='melty-', dir=str(shm) if shm.is_dir() and os.access(shm, os.W_OK) else None)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(value)
    return Path(path)


HARDEN = r"""$ErrorActionPreference='Stop'
$p='C:\melty-export'
if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
foreach ($x in @('C:\',$p)) {
  $i=Get-Item -LiteralPath $x -Force
  if (-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe folder' }
}
$k='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
New-Item -Path $k -Force | Out-Null
foreach ($v in @('fDisableClip','fDisableCdm','fDisableCpm','fDisableCcm','fDisableLPT','fDisablePNPRedir','fDisableCameraRedir','fDisableAudioCapture','fDisableWebAuthn','fDisableLocationRedir')) {
  New-ItemProperty -Path $k -Name $v -Value 1 -PropertyType DWord -Force | Out-Null
}
New-ItemProperty -Path $k -Name fEnableSmartCard -Value 0 -PropertyType DWord -Force | Out-Null
try { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Server Manager\' -TaskName 'ServerManager' | Out-Null } catch {}
Write-Output 'MELTY_READY'
"""


def run_guest(az, rg, name, script):
    return az('vm', 'run-command', 'invoke', '-g', rg, '--name', name,
              '--command-id', 'RunPowerShellScript', '--scripts', script, raw=True).strip('\r\n')


def wait_guest_agent(az, rg, name, limit=420, sleep=None):
    # Run Command queues behind the guest agent; waiting here names a slow first boot instead of a silent timeout.
    deadline = time.monotonic() + limit
    while True:
        try:
            view = (az('vm', 'get-instance-view', '-g', rg, '--name', name) or {}).get('instanceView') or {}
            ready = any(s.get('displayStatus') == 'Ready' for s in (view.get('vmAgent') or {}).get('statuses', []))
        except AzureError:
            ready = False
        if ready:
            return
        if time.monotonic() > deadline:
            raise ValidationError('Guest agent not ready')
        (sleep or time.sleep)(15)


def check_free(az, rg, name):
    if any(r['name'].startswith(name) or r['name'] == 'shutdown-computevm-' + name
           for r in az('resource', 'list', '-g', rg)):
        raise ValidationError('Box name already exists')


def provision(az, inputs, rg, name, created, sleep=None):
    cidr = valid_cidr(inputs.get('allow_cidr'))
    end = valid_expires(inputs.get('expires'), created)
    size = valid_size(inputs.get('size') or SIZES[0])
    region = inputs.get('region') or 'eastus'
    if not re.fullmatch(r'[a-z0-9]{1,40}', region):
        raise ValidationError('Invalid region')
    tags = ['owner=agent', 'box=' + name, 'purpose=melty-lab', 'created=' + stamp(created), 'expires=' + stamp(end)]
    g = ['-g', rg]
    common = [*g, '--location', region, '--tags', *tags]
    step('network')
    az('network', 'nsg', 'create', '--name', name + '-nsg', *common)  # recovery anchor
    rules = [('rdp', 100, 'Inbound', 'Allow', cidr, '*', 'Tcp', '3389'),
             ('deny-other-inbound', 4096, 'Inbound', 'Deny', '*', '*', '*', '*')]
    rules += [('deny-out-' + str(i), 100 + i, 'Outbound', 'Deny', '*', dest, '*', '*')
              for i, dest in enumerate(['VirtualNetwork', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])]
    for rule, priority, direction, access, src, dest, protocol, port in rules:
        az('network', 'nsg', 'rule', 'create', *g, '--nsg-name', name + '-nsg',
           '--name', rule, '--priority', str(priority), '--direction', direction,
           '--access', access, '--protocol', protocol, '--source-address-prefixes', src,
           '--source-port-ranges', '*', '--destination-address-prefixes', dest,
           '--destination-port-ranges', port)
    az('network', 'vnet', 'create', '--name', name + '-vnet', *common,
       '--address-prefixes', '10.43.0.0/24', '--subnet-name', 'box', '--subnet-prefixes', '10.43.0.0/24')
    az('network', 'public-ip', 'create', '--name', name + '-ip', *common,
       '--sku', 'Standard', '--allocation-method', 'Static', '--version', 'IPv4')
    az('network', 'nic', 'create', '--name', name + '-nic', *common, '--vnet-name', name + '-vnet',
       '--subnet', 'box', '--network-security-group', name + '-nsg', '--public-ip-address', name + '-ip')
    az.secret = password()
    mask(az.secret)
    path = secret_file(az.secret)
    try:
        step('vm create')
        az('vm', 'create', '--name', name, *common, '--size', size, '--nics', name + '-nic',
           '--image', IMAGE, '--admin-username', ADMIN, '--admin-password', '@' + str(path),
           '--computer-name', 'melty' + name[-6:], '--os-disk-name', name + '-os',
           '--storage-sku', 'Premium_LRS', '--security-type', 'Standard',
           '--os-disk-delete-option', 'Detach', '--nic-delete-option', 'Detach')
    finally:
        path.unlink(missing_ok=True)
    az('resource', 'tag', *g, '--resource-type', 'Microsoft.Compute/disks', '--name', name + '-os', '--tags', *tags)
    az('vm', 'boot-diagnostics', 'disable', *g, '--name', name)
    identity = (az('vm', 'show', *g, '--name', name) or {}).get('identity') or {}
    if identity.get('type') not in (None, 'None') or any(identity.get(k) for k in
            ('principalId', 'tenantId', 'userAssignedIdentities')):
        raise ValidationError('VM unexpectedly has an identity')
    # Daily at the expiry minute (UTC): compute stops at expiry even if deletion is late.
    az('vm', 'auto-shutdown', *g, '--name', name, '--time', end.strftime('%H%M'), '--location', region)
    az('resource', 'tag', *g, '--resource-type', 'Microsoft.DevTestLab/schedules',
       '--name', 'shutdown-computevm-' + name, '--tags', *tags)
    step('guest agent')
    wait_guest_agent(az, rg, name, sleep=sleep)
    step('guest hardening')
    if run_guest(az, rg, name, HARDEN) != 'MELTY_READY':
        raise ValidationError('Guest hardening did not confirm success')
    step('ready')
    return end


def down(az, name, rg):
    name_ok(name)
    resources = az('resource', 'list', '-g', rg)
    selected = [r for r in resources if (r.get('tags') or {}).get('owner') == 'agent'
                and (r.get('tags') or {}).get('box') == name]
    if selected:  # recover only exact companions, never another owner's resource
        for r in resources:
            kind = r['type'].lower()
            if (r.get('tags') or {}).get('owner') or r in selected:
                continue
            if kind == DISK and r['name'] == name + '-os':
                selected.append(r)
            if kind == SCHEDULE and r['name'] == 'shutdown-computevm-' + name:
                target = az('resource', 'show', '--ids', r['id']).get('properties', {}).get('targetResourceId', '')
                expected = r['id'].split('/providers/')[0] + '/providers/Microsoft.Compute/virtualMachines/' + name
                if target.lower() == expected.lower():
                    selected.append(r)
    order = {VM: 0, 'microsoft.network/networkinterfaces': 1, DISK: 2,
             'microsoft.network/publicipaddresses': 3, 'microsoft.network/networksecuritygroups': 4,
             'microsoft.network/virtualnetworks': 5, SCHEDULE: 6}
    pending = sorted(selected, key=lambda r: order.get(r['type'].lower(), 7))
    for attempt in range(3):
        try:
            while pending:
                az('resource', 'delete', '--ids', pending[0]['id'])
                pending.pop(0)
            break
        except AzureError:
            if attempt == 2:
                raise
            time.sleep(10)
    ids = {r['id'] for r in selected}
    if any(r['id'] in ids or ((r.get('tags') or {}).get('owner') == 'agent' and
           (r.get('tags') or {}).get('box') == name) for r in az('resource', 'list', '-g', rg)):
        raise ValidationError('Resources remain; rerun melty-down')
    return len(selected)


def report(fields):
    for k, v in fields.items():
        print(k + ': ' + v, flush=True)
    for var, fmt in (('GITHUB_OUTPUT', '%s=%s\n'), ('GITHUB_STEP_SUMMARY', '%s: %s\n\n')):
        if os.environ.get(var):
            with open(os.environ[var], 'a') as f:
                for k, v in fields.items():
                    f.write(fmt % (k, v))


def main(argv=None, az=None, now=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (['up'], ['down']):
        raise ValidationError('usage: melty-lab.py up|down (inputs come from the workflow event)')
    inputs = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()).get('inputs', {}) or {}
    if inputs.get('allow_cidr'):
        mask(inputs['allow_cidr'])
        mask(str(inputs['allow_cidr']).split('/')[0])
    rg = os.environ['AZURE_RESOURCE_GROUP']
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,79}', rg):
        raise ValidationError('Invalid resource group')
    az = az or Az()
    if argv == ['up']:
        created = (now or dt.datetime.now(UTC)).replace(second=0, microsecond=0)
        # Validate every input before touching Azure.
        valid_cidr(inputs.get('allow_cidr'))
        valid_expires(inputs.get('expires'), created)
        valid_size(inputs.get('size') or SIZES[0])
        name = 'melty-lab-' + secrets.token_hex(3)
        step('login')
        login(az)
        check_free(az, rg, name)
        try:
            end = provision(az, inputs, rg, name, created)
        except Exception:
            step('cleanup after failure')
            down(az, name, rg)
            raise
        report({'name': name, 'expires': stamp(end), 'resource_group': rg})
    else:
        name = name_ok(inputs.get('name'))
        step('login')
        login(az)
        count = down(az, name, rg)
        report({'name': name, 'deleted': str(count)})


if __name__ == '__main__':
    try:
        main()
    except (ValidationError, AzureError) as exc:
        print(masked(str(exc)), file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print('Operation failed (' + type(exc).__name__ + '); details withheld', file=sys.stderr)
        sys.exit(1)
