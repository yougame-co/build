#!/usr/bin/env python3
"""Azure test box lifecycle. CLI responses/errors stay private; no artifacts."""
import base64
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request

UTC = dt.timezone.utc
ADMIN = 'ygagent'
VM_TYPE = 'microsoft.compute/virtualmachines'
DISK_TYPE = 'microsoft.compute/disks'
SNAPSHOT_TYPE = 'microsoft.compute/snapshots'


# Windows Server 2025 ships OpenSSH Server installed (only enabled by the guest script); 2022 downloads it as a
# Feature on Demand, which ran past the 30-min job limit on 10-31 (box run 41177326975).
IMAGES = {'windows-2025': 'MicrosoftWindowsServer:WindowsServer:2025-datacenter-g2:latest',
          'windows-2022': 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-g2:latest',
          'ubuntu-24.04': 'Canonical:ubuntu-24_04-lts:server:latest'}
# Per-call client timeouts (seconds): a stuck call fails with its step named and cleanup still runs inside the job.
TIMEOUTS = {('vm', 'create'): 900, ('vm', 'run-command'): 900}
STARTED = time.monotonic()

SIZES = {'Standard_D2s_v6', 'Standard_D4s_v6', 'Standard_D2as_v7', 'Standard_D4as_v7',
         'Standard_D2ps_v6', 'Standard_D4ps_v6', 'Standard_NV4as_v4', 'Standard_NV8as_v4',
         'Standard_NC4as_T4_v3'}
# NVIDIA T4 (4 vCPU, pay-as-you-go eastus ~$0.53/h Linux, ~$0.71/h Windows) for tests that need a real GPU only
# (Luis 10-31: "make sure not use much more gpu than is necessary. Be cost mindful"): lifetime capped at 2 hours.
GPU_MAX_HOURS = {'Standard_NC4as_T4_v3': 2}


class ValidationError(Exception):
    pass


def mask(value):
    # Escape workflow-command metacharacters, including hostile dispatch input.
    value = str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::add-mask::' + value, flush=True)


def step(name):
    # Progress lines carry only fixed step names, so a slow step is visible in the public log.
    print('[+%ds] %s' % (time.monotonic() - STARTED, name), flush=True)


def az(*args, timeout=None):
    # az 2.91 can crash with an import deadlock (_DeadlockError on requests.structures) when its telemetry thread
    # imports at the same time: telemetry off, and one retry on exactly that crash (box run 41177256736).
    env = {**os.environ, 'AZURE_CORE_COLLECT_TELEMETRY': 'false'}
    limit = timeout or TIMEOUTS.get(tuple(args[:2]), 300)
    for attempt in range(3):
        try:
            result = subprocess.run(['az', *args, '--only-show-errors', '--output', 'json'],
                                    capture_output=True, text=True, check=False, env=env, timeout=limit)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Azure operation failed: ' + ' '.join(args[:2]) + ' [Timeout]') from None
        if not (result.returncode and '_DeadlockError' in (result.stderr or '')):
            break
    if result.returncode:
        # Azure errors can repeat passwords, request bodies or network rules: keep only the error CODE
        # (letters only, e.g. AuthorizationFailed), which is safe for a public log.
        code = re.search(r'\(([A-Z][A-Za-z]{2,63})\)|"code":\s*"([A-Z][A-Za-z]{2,63})"|Code: ([A-Z][A-Za-z]{2,63})', result.stderr or '')
        if not code and re.search(r'(?i)usage error|unrecognized arguments|the following arguments are required|invalid choice', result.stderr or ''):
            code = re.search(r'(CliUsage)', 'CliUsage')
        code = next((g for g in code.groups() if g), None) if code else None
        detail = ''
        if args and args[0] == 'network':
            # Network commands carry no secrets: show the CLI's own first error line, with every IP and GUID masked
            # (yougame-lead 10-31: the failing nsg create never reached Azure, so the reason is client-side).
            lines = [l for l in (result.stderr or '').splitlines() if l.strip()]
            # A CLI crash prints a traceback: its last line names the exception, which is what matters.
            exc = [l.strip() for l in lines if re.match(r'\s*[A-Za-z_.]*(?:Error|Exception)\b', l)]
            line = ('CLI crash: ' + exc[-1]) if exc and 'traceback' in (lines[0] if lines else '').lower() else (lines[0] if lines else '')
            line = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b', 'x.x.x.x', line)
            line = re.sub(r'\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '<guid>', line)
            line = re.sub(r'(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b', '<ipv6>', line)
            detail = ' | ' + line[:300] if line else ''
        raise RuntimeError('Azure operation failed: ' + ' '.join(args[:2]) + (' [' + code + ']' if code else '') + detail)
    return json.loads(result.stdout) if result.stdout.strip() else None


def cli_version():
    try:
        v = az('version')
        print('az CLI ' + str((v or {}).get('azure-cli', '?')))
    except RuntimeError:
        pass


def login():
    mask(ADMIN)
    cli_version()
    bearer = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    mask(bearer)
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    url += ('&' if '?' in url else '?') + urllib.parse.urlencode(
        {'audience': 'api://AzureADTokenExchange'})
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + bearer})
    with urllib.request.urlopen(request, timeout=30) as response:
        token = json.load(response)['value']
    mask(token)
    az('login', '--service-principal', '-u', os.environ['AZURE_CLIENT_ID'],
       '-t', os.environ['AZURE_TENANT_ID'], '--federated-token', token,
       '--allow-no-subscriptions')
    az('account', 'set', '--subscription', os.environ['AZURE_SUBSCRIPTION_ID'])


def guest_status(rg, name):
    # Fixed status words only (agent "Ready", extension provisioning codes); extension messages can carry script
    # output, so they never reach the public log.
    view = (az('vm', 'get-instance-view', *rg, '--name', name) or {}).get('instanceView') or {}
    clean = lambda v: re.sub(r'[^A-Za-z/ ._-]', '', str(v))[:60]
    agent = ','.join(clean(s.get('displayStatus', '')) for s in (view.get('vmAgent') or {}).get('statuses', []))
    exts = ' '.join(clean(e.get('name', '?')) + '=' + ','.join(clean(s.get('code', '')) for s in e.get('statuses', []))
                    for e in view.get('extensions') or [])
    return agent, exts


def wait_guest_agent(rg, name, limit=420):
    # Run Command queues behind the guest agent; waiting here names a slow first boot instead of a silent timeout.
    # One failed status call is not a verdict: keep polling and report the last error only at the deadline.
    deadline = time.monotonic() + limit
    while True:
        try:
            agent, error = guest_status(rg, name)[0], None
        except RuntimeError as exc:
            agent, error = '', exc
        if agent == 'Ready':
            return
        if time.monotonic() > deadline:
            if error:
                raise error
            raise RuntimeError('Guest agent not ready: ' + (agent or 'no status'))
        time.sleep(15)


# The setup script runs as a SYSTEM scheduled task so Run Command returns at once: Run Command runs one script at a
# time per VM, so a stuck script would also block any later read of its log. C:\yg is Administrators/SYSTEM only.
LAUNCH = r'''$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path 'C:\yg' | Out-Null
& icacls.exe 'C:\yg' /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'setup folder ACL failed' }
[IO.File]::WriteAllBytes('C:\yg\ssh-setup.ps1', [Convert]::FromBase64String('__SCRIPT_B64__'))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\yg\ssh-setup.ps1'
Register-ScheduledTask -TaskName 'YouGame-SSH-Setup' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'YouGame-SSH-Setup'
Write-Output 'YG_SETUP_STARTED'
'''
POLL = r'''if (Test-Path 'C:\yg\ssh-setup.log') { Get-Content 'C:\yg\ssh-setup.log' -Tail 40 } else { 'YG_NO_LOG' }'''
# Only the setup script's own fixed lines reach the public log.
SETUP_LINE = re.compile(r'\[\+\d{1,5}s\] [a-z ]{1,40}|YG_SSH_READY|YG_NO_LOG|YG_FAIL [a-z ]{1,40}')


def run_command(rg, name, script, timeout):
    result = az('vm', 'run-command', 'invoke', *rg, '--name', name,
                '--command-id', 'RunPowerShellScript', '--scripts', script, timeout=timeout)
    return '\n'.join(v.get('message', '') for v in (result or {}).get('value', []))


def guest_ssh_setup(rg, name, script, limit=600):
    try:
        started = run_command(rg, name, LAUNCH.replace('__SCRIPT_B64__', base64.b64encode(script.encode()).decode()), 300)
        if 'YG_SETUP_STARTED' not in started:
            raise RuntimeError('Windows SSH setup did not start')
        step('guest setup started')
        deadline, seen, last = time.monotonic() + limit, set(), 'no log'
        while True:
            lines = [l.strip() for l in run_command(rg, name, POLL, 300).splitlines()]
            for line in lines:
                if SETUP_LINE.fullmatch(line) and line not in seen:
                    seen.add(line)
                    print('guest: ' + line, flush=True)
                    last = line
            if 'YG_SSH_READY' in seen:
                return
            fail = next((l for l in seen if l.startswith('YG_FAIL ')), None)
            if fail:
                raise RuntimeError('Windows SSH setup failed at ' + fail.removeprefix('YG_FAIL '))
            if time.monotonic() > deadline:
                raise RuntimeError('Windows SSH setup stuck after: ' + last)
            time.sleep(10)
    except RuntimeError:
        try:
            print('guest status: agent=%s extensions=%s' % guest_status(rg, name), flush=True)
        except RuntimeError:
            pass
        raise


def timestamp(value):
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (ValueError, TypeError):
        return None


def inventory():
    # The REST API supports createdTime expansion; az resource list does not.
    base = ('https://management.azure.com/subscriptions/' +
            urllib.parse.quote(os.environ['AZURE_SUBSCRIPTION_ID'], safe='') +
            '/resourceGroups/' + urllib.parse.quote(os.environ['AZURE_RESOURCE_GROUP'], safe='') +
            '/resources')
    url = base + '?api-version=2021-04-01&$expand=createdTime,changedTime'
    resources = []
    seen = set()
    while url:
        if not url.startswith(base + '?') or url in seen:
            raise RuntimeError('Unexpected resource inventory continuation')
        seen.add(url)
        page = az('rest', '--method', 'get', '--url', url)
        resources.extend(page['value'])
        url = page.get('nextLink')
    return resources


def owned(resource):
    return (resource.get('tags') or {}).get('owner') == 'agent'


def disk_companions(resources, boxes):
    # VM-created OS disks cannot receive tags atomically. Recover the short
    # create/tag gap after runner cancellation using an explicitly named disk
    # and an independently tagged lifecycle anchor. Never adopt someone else's tag.
    return [r for r in resources if r['type'].lower() == DISK_TYPE
            and r['name'] in {b + '-os' for b in boxes}
            and not (r.get('tags') or {}).get('owner')]


def delete_resources(resources):
    order = {VM_TYPE: 0, 'microsoft.network/networkinterfaces': 1,
             DISK_TYPE: 2, 'microsoft.network/publicipaddresses': 3,
             'microsoft.network/networksecuritygroups': 4,
             'microsoft.network/virtualnetworks': 5}
    pending = sorted(resources, key=lambda r: order.get(r['type'].lower(), 6))
    for attempt in range(3):
        failed = []
        for resource in pending:
            try:
                az('resource', 'delete', '--ids', resource['id'])
                print('Deleted ' + resource['name'])
            except RuntimeError:
                failed.append(resource)
        if not failed:
            return
        pending = failed
        if attempt < 2:
            time.sleep(10)
    raise RuntimeError('Resource deletion incomplete; rerun cleanup')


def down(name):
    if not re.fullmatch(r'ygbox-[a-z0-9-]+-[0-9]+', name):
        raise ValidationError('Invalid box name')
    resources = inventory()
    if not any(r['name'] == name and r['type'].lower() == VM_TYPE and owned(r)
               for r in resources):
        raise ValidationError('Refusing deletion: VM must exist and have owner=agent')
    selected = [r for r in resources if owned(r) and
                ((r.get('tags') or {}).get('box') == name or
                 (r['name'] == name and r['type'].lower() == VM_TYPE))]
    delete_resources(selected + disk_companions(resources, {name}))
    report_leftovers({name})


def reap(now=None):
    now = now or dt.datetime.now(UTC)
    resources = inventory()
    selected = []
    boxes = set()
    for resource in resources:
        if not owned(resource):
            continue
        tags = (resource.get('tags') or {})
        expires = timestamp(tags.get('expires'))
        created = (timestamp(resource.get('createdTime')) or
                   timestamp((resource.get('systemData') or {}).get('createdAt')) or
                   timestamp(tags.get('created')))
        # Fail closed for malformed/missing lifecycle timestamps. Server creation
        # time takes precedence so extending expires cannot bypass the 12h cap.
        if (expires is None or expires <= now or created is None or
                created <= now - dt.timedelta(hours=12)):
            selected.append(resource)
            box = tags.get('box', '')
            if re.fullmatch(r'ygbox-[a-z0-9-]+-[0-9]+', box):
                boxes.add(box)
    delete_resources(selected + disk_companions(resources, boxes))
    report_leftovers(boxes)


def report_leftovers(boxes):
    # Compliance (10-31): a box that held a game disc must leave no disk or snapshot behind. Names only.
    # The resource list can lag a delete by seconds, so anything left is read once more before it counts.
    for attempt in range(2):
        left = [r for r in inventory() if r['type'].lower() in (DISK_TYPE, SNAPSHOT_TYPE)]
        if not left or attempt:
            break
        time.sleep(30)
    print('Disks and snapshots left in the group: ' + (', '.join(sorted(r['name'] for r in left)) or 'none'))
    stale = sorted(r['name'] for r in left if (r.get('tags') or {}).get('box') in boxes or
                   any(r['name'].startswith(b + '-') for b in boxes))
    if stale:
        raise RuntimeError('A deleted box left a disk or snapshot behind: ' + ', '.join(stale))


def up(inputs):
    key_file = Path('keys/agent-ssh.pub')
    if not key_file.is_file():
        raise ValidationError('keys/agent-ssh.pub missing (security places it)')
    label = inputs['label']
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?', label):
        raise ValidationError('label must be 1-32 lowercase letters, digits or hyphens; alphanumeric ends')
    try:
        network = ipaddress.ip_network(inputs['allow_cidr'], strict=True)
    except ValueError:
        raise ValidationError('allow_cidr must be a public IPv4 address with /32') from None
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValidationError('allow_cidr must be a public IPv4 address with /32')
    mask(str(network.network_address))
    os_name = inputs.get('os', 'windows-2025')
    if os_name not in IMAGES:
        raise ValidationError('Invalid os')
    hours = inputs.get('hours', '2')
    if not re.fullmatch(r'(?:[1-9]|1[0-2])', str(hours)):
        raise ValidationError('hours must be an integer from 1 to 12')
    size, region = inputs.get('size', 'Standard_D2s_v6'), inputs.get('region', 'eastus')
    # Costed sizes only (security-lead 10-31): pay-as-you-go eastus ~$0.04-0.71/h; anything else needs a costed PR.
    if size not in SIZES or not re.fullmatch(r'[a-z0-9]+', region):
        raise ValidationError('Invalid size or region (sizes: ' + ', '.join(sorted(SIZES)) + ')')
    if int(hours) > GPU_MAX_HOURS.get(size, 12):
        raise ValidationError(f'{size} boxes live at most {GPU_MAX_HOURS[size]} hours')
    # Keep only key type/base64, never comments identifying its owner. Reject options.
    key_parts = key_file.read_text().strip().split()
    if len(key_file.read_text().strip().splitlines()) != 1 or len(key_parts) < 2:
        raise ValidationError('Expected exactly one SSH public key')
    if key_parts[0] not in ('ssh-ed25519', 'ssh-rsa') or not re.fullmatch(r'[A-Za-z0-9+/=]+', key_parts[1]):
        raise ValidationError('Invalid SSH public key')
    key = ' '.join(key_parts[:2])
    step('login')
    login()
    name = 'ygbox-' + label + '-' + os.environ['GITHUB_RUN_ID']
    now = dt.datetime.now(UTC)
    expires = (now + dt.timedelta(hours=int(hours))).strftime('%Y-%m-%dT%H:%M:%SZ')
    tags = ['owner=agent', 'purpose=' + label, 'expires=' + expires,
            'run=' + os.environ['GITHUB_RUN_ID'], 'box=' + name,
            'created=' + now.strftime('%Y-%m-%dT%H:%M:%SZ')]
    rg = ['--resource-group', os.environ['AZURE_RESOURCE_GROUP']]
    common = [*rg, '--location', region, '--tags', *tags]
    # A rerun must never reset/overwrite a live VM's password or SSH configuration.
    if any(r['name'] == name for r in inventory()):
        raise ValidationError('Box already exists; use box-down before retrying')
    windows = os_name.startswith('windows-')
    try:
        step('network')
        az('network', 'nsg', 'create', '--name', name + '-nsg', *common)
        for rule, priority, protocol, ports, source, access in [
            ('deny-other-inbound', '4096', '*', '*', '*', 'Deny'),
            ('agent-ssh', '100', 'Tcp', '22', str(network), 'Allow'),
            ('agent-link', '110', 'Udp', '51600-51699', str(network), 'Allow'),
        ]:
            az('network', 'nsg', 'rule', 'create', *rg, '--nsg-name', name + '-nsg',
               '--name', rule, '--priority', priority, '--direction', 'Inbound',
               '--access', access, '--protocol', protocol,
               '--source-address-prefixes', source, '--source-port-ranges', '*',
               '--destination-address-prefixes', '*', '--destination-port-ranges', ports)
        az('network', 'vnet', 'create', '--name', name + '-vnet', *common,
           '--address-prefixes', '10.42.0.0/24', '--subnet-name', 'box',
           '--subnet-prefixes', '10.42.0.0/24')
        az('network', 'public-ip', 'create', '--name', name + '-ip', *common,
           '--sku', 'Standard', '--allocation-method', 'Static', '--version', 'IPv4')
        az('network', 'nic', 'create', '--name', name + '-nic', *common,
           '--vnet-name', name + '-vnet', '--subnet', 'box',
           '--network-security-group', name + '-nsg', '--public-ip-address', name + '-ip')
        vm_args = ['vm', 'create', '--name', name, *common, '--size', size,
                   '--nics', name + '-nic', '--admin-username', ADMIN,
                   '--computer-name', 'ygbox' + os.environ['GITHUB_RUN_ID'][-10:],
                   '--os-disk-name', name + '-os', '--storage-sku', 'Premium_LRS',
                   '--security-type', 'Standard',
                   '--os-disk-delete-option', 'Detach', '--nic-delete-option', 'Detach']
        vm_args += ['--image', IMAGES[os_name]]
        if windows:
            password = 'Yg9!' + secrets.token_urlsafe(32)
            mask(password)
            vm_args += ['--admin-password', password]
        else:
            vm_args += ['--authentication-type', 'ssh', '--ssh-key-values', str(key_file)]
        step('vm create')
        az(*vm_args)
        disk = next(r for r in inventory() if r['name'] == name + '-os' and r['type'].lower() == DISK_TYPE)
        az('resource', 'tag', '--ids', disk['id'], '--tags', *tags)
        if windows:
            step('guest agent')
            wait_guest_agent(rg, name)
            step('guest ssh setup')
            guest_ssh_setup(rg, name, Path('scripts/test-boxes-windows.ps1').read_text().replace('__PUBLIC_KEY__', key))
        ip = az('network', 'public-ip', 'show', *rg, '--name', name + '-ip')['ipAddress']
        step('ready')
    except Exception:
        # Delete even a partially provisioned VM and recover its untagged OS disk.
        step('cleanup after failure')
        resources = inventory()
        selected = [r for r in resources if owned(r) and (r.get('tags') or {}).get('box') == name]
        delete_resources(selected + disk_companions(resources, {name}))
        raise
    output = {'name': name, 'public_ip': ip, 'os': os_name, 'expires': expires}
    for k, v in output.items():
        print(k + ': ' + v)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        for k, v in output.items():
            f.write(k + '=' + v + '\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        for k, v in output.items():
            f.write(k + ': ' + v + '\n\n')


def main():
    # A dispatch of a workflow without inputs (the reaper) carries "inputs": null.
    inputs = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()).get('inputs') or {}
    if inputs.get('allow_cidr'):
        mask(inputs['allow_cidr'])
        mask(inputs['allow_cidr'].split('/')[0])
    if sys.argv[1] == 'up':
        up(inputs)
    elif sys.argv[1] == 'down':
        # Check syntax before obtaining a token.
        if not re.fullmatch(r'ygbox-[a-z0-9-]+-[0-9]+', inputs['name']):
            raise ValidationError('Invalid box name')
        login()
        down(inputs['name'])
    elif sys.argv[1] == 'reap':
        login()
        reap()
    else:
        raise ValidationError('Unknown lifecycle command')


if __name__ == '__main__':
    try:
        main()
    except ValidationError as exc:
        print('::error::' + str(exc))
        sys.exit(1)
    except RuntimeError as exc:
        # az() messages carry only the operation (e.g. "account set"), never Azure's own text.
        print('::error::Test box operation failed at ' + str(exc).removeprefix('Azure operation failed: ')
              + '; Azure details suppressed for public log privacy')
        sys.exit(1)
    except Exception as exc:
        # The line number says where without printing any Azure data.
        tb = exc.__traceback__
        while tb and tb.tb_next:
            tb = tb.tb_next
        line = tb.tb_lineno if tb else 0
        print('::error::Test box operation failed (' + type(exc).__name__ + ' at line ' + str(line)
              + '); details suppressed for public log privacy')
        sys.exit(1)
