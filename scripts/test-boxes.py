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
GALLERY = 'yg_test_boxes'
IMAGE_NAME = r'[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?'
SSH_SETUP_TASK, SSH_SETUP_LOG = 'SSH-Setup', 'ssh-setup.log'
DISC_SCAN_TASK, DISC_SCAN_RESULT = 'Disc-Scan', 'disc-scan.txt'
DISC_SCAN = r"""
$ErrorActionPreference = 'Stop'
$extensions = @('.iso', '.gcm', '.rvz', '.ciso', '.wbfs', '.wia', '.gcz', '.nkit', '.dol', '.elf', '.rom')
$systemFiles = @('c:\pagefile.sys', 'c:\swapfile.sys', 'c:\hiberfil.sys')
$discCount, $largeCount, $found, $errors = 0, 0, 0, 0
$stack = [System.Collections.Generic.Stack[string]]::new()
$stack.Push('C:\')
while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    try {
        foreach ($entry in [System.IO.DirectoryInfo]::new($dir).EnumerateFileSystemInfos()) {
            if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
            if ($entry.Attributes -band [System.IO.FileAttributes]::Directory) {
                $stack.Push($entry.FullName)
            } else {
                $disc = $extensions -contains $entry.Extension.ToLowerInvariant()
                $large = $entry.Length -gt 1GB -and $systemFiles -notcontains $entry.FullName.ToLowerInvariant()
                if ($disc) { $discCount++ }
                if ($large) { $largeCount++ }
                if ($disc -or $large) { $found++ }
            }
        }
    } catch {
        $errors++
    }
}
if ($errors -gt 0) { $result = 'YG_SCAN_ERROR ' + $errors + ' ' + $found }
elseif ($found -gt 0) { $result = 'YG_DISC_FOUND ' + $discCount + ' ' + $largeCount }
else { $result = 'YG_NO_DISC' }
Set-Content -Path 'C:\yg\disc-scan.txt' -Value $result -Encoding ascii
"""


# Windows Server 2025 ships OpenSSH Server installed (only enabled by the guest script); 2022 downloads it as a
# Feature on Demand, which ran past the 30-min job limit on 10-31 (box run 41177326975).
IMAGES = {'windows-2025': 'MicrosoftWindowsServer:WindowsServer:2025-datacenter-g2:latest',
          'windows-2022': 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-g2:latest',
          'ubuntu-24.04': 'Canonical:ubuntu-24_04-lts:server:latest'}
# Per-call client timeouts (seconds): a stuck call fails with its step named and cleanup still runs inside the job.
TIMEOUTS = {('vm', 'create'): 900, ('vm', 'run-command'): 900,
            ('sig', 'create'): 900, ('sig', 'image-definition'): 900,
            ('sig', 'image-version', 'create'): 3600}
STARTED = time.monotonic()

SIZES = {'Standard_D2s_v6', 'Standard_D4s_v6', 'Standard_D2as_v7', 'Standard_D4as_v7',
         'Standard_D2ps_v6', 'Standard_D4ps_v6', 'Standard_NV4as_v4', 'Standard_NV8as_v4'}


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
    limit = timeout or TIMEOUTS.get(tuple(args[:3]), TIMEOUTS.get(tuple(args[:2]), 300))
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


# Guest scripts run as SYSTEM scheduled tasks so Run Command returns at once: Run Command runs one script at a
# time per VM, so a stuck script would also block any later read of its log. C:\yg is Administrators/SYSTEM only.
LAUNCH = r'''$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path 'C:\yg' | Out-Null
& icacls.exe 'C:\yg' /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'setup folder ACL failed' }
if ('__TASK__' -ne 'SSH-Setup') {
    Remove-Item 'C:\yg\__RESULT_FILE__' -Force -ErrorAction SilentlyContinue
    if (Test-Path 'C:\yg\__RESULT_FILE__') { throw 'task result reset failed' }
}
[IO.File]::WriteAllBytes('C:\yg\__TASK__.ps1', [Convert]::FromBase64String('__SCRIPT_B64__'))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\yg\__TASK__.ps1'
Register-ScheduledTask -TaskName 'YouGame-__TASK__' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'YouGame-__TASK__'
Write-Output 'YG_TASK_STARTED'
'''
POLL = r'''if (Test-Path 'C:\yg\__RESULT_FILE__') { Get-Content 'C:\yg\__RESULT_FILE__' -Tail 40 } else { 'YG_NO_LOG' }'''
UNREGISTER = "Unregister-ScheduledTask -TaskName 'YouGame-__TASK__' -Confirm:$false -ErrorAction SilentlyContinue"
# Only the setup script's own fixed lines reach the public log.
SETUP_LINE = re.compile(r'\[\+\d{1,5}s\] [a-z ]{1,40}|YG_SSH_READY|YG_NO_LOG|YG_FAIL [a-z ]{1,40}')


def run_command(rg, name, script, timeout):
    result = az('vm', 'run-command', 'invoke', *rg, '--name', name,
                '--command-id', 'RunPowerShellScript', '--scripts', script, timeout=timeout)
    return '\n'.join(v.get('message', '') for v in (result or {}).get('value', []))


def guest_task(rg, name, task, script, result_file, limit, launch_timeout=300, poll_timeout=300, *, done):
    """Launch a fixed guest task and pass stripped, nonblank result lines to done.

    Return the last lines on completion or at the deadline; callers validate the result.
    The polling limit starts after launch, and each Run Command has its own timeout.
    """
    if not re.fullmatch(r'[A-Za-z-]{1,40}', task):
        raise ValidationError('Invalid guest task name')
    if not re.fullmatch(r'[a-z-]{1,40}\.(log|txt)', result_file):
        raise ValidationError('Invalid guest task result file')
    launch = LAUNCH.replace('__TASK__', task).replace('__RESULT_FILE__', result_file)
    launch = launch.replace('__SCRIPT_B64__', base64.b64encode(script.encode()).decode())
    if 'YG_TASK_STARTED' not in run_command(rg, name, launch, launch_timeout):
        raise RuntimeError('Windows SSH setup did not start' if task == SSH_SETUP_TASK else 'Guest task did not start')
    if task == SSH_SETUP_TASK:
        step('guest setup started')
    poll = POLL.replace('__RESULT_FILE__', result_file)
    deadline = time.monotonic() + limit
    while True:
        lines = [line.strip() for line in run_command(rg, name, poll, poll_timeout).splitlines() if line.strip()]
        if done(lines):
            # SSH setup unregisters itself in its own finally block.
            if task != SSH_SETUP_TASK:
                run_command(rg, name, UNREGISTER.replace('__TASK__', task), poll_timeout)
            return lines
        if time.monotonic() > deadline:
            return lines
        time.sleep(10)


def guest_ssh_setup(rg, name, script, limit=600):
    seen, last = set(), 'no log'

    def done(lines):
        nonlocal last
        for line in lines:
            if SETUP_LINE.fullmatch(line) and line not in seen:
                seen.add(line)
                print('guest: ' + line, flush=True)
                last = line
        if 'YG_SSH_READY' in seen:
            return True
        fail = next((l for l in seen if l.startswith('YG_FAIL ')), None)
        if fail:
            raise RuntimeError('Windows SSH setup failed at ' + fail.removeprefix('YG_FAIL '))
        return False

    try:
        guest_task(rg, name, SSH_SETUP_TASK, script, SSH_SETUP_LOG, limit, done=done)
        if 'YG_SSH_READY' not in seen:
            raise RuntimeError('Windows SSH setup stuck after: ' + last)
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
                   timestamp(resource.get('systemData', {}).get('createdAt')) or
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


def image_versions(rg, image):
    versions = az('sig', 'image-version', 'list', *rg, '--gallery-name', GALLERY,
                  '--gallery-image-definition', image) or []
    return sorted(versions, key=lambda v: tuple(int(n) for n in v['name'].split('.')))


def capture(inputs):
    name, image = inputs['name'], inputs['image']
    if not re.fullmatch(r'ygbox-[a-z0-9-]+-[0-9]+', name):
        raise ValidationError('Invalid box name')
    if not re.fullmatch(IMAGE_NAME, image):
        raise ValidationError('Invalid image name')
    if inputs.get('no_disc') != 'yes':
        raise ValidationError('Refusing capture: confirm no game disc, ROM or signed-in account is on the box')
    step('login')
    login()
    vm = next((r for r in inventory() if r['name'] == name and
               r['type'].lower() == VM_TYPE and owned(r)), None)
    if vm is None:
        raise ValidationError('Refusing capture: VM must exist and have owner=agent')
    if (vm.get('tags') or {}).get('image_builder') != 'yes':
        raise ValidationError('Refusing capture: only a box created with image_builder=yes can be captured')
    rg = ['--resource-group', os.environ['AZURE_RESOURCE_GROUP']]
    details = az('vm', 'show', *rg, '--name', name)
    if (details.get('storageProfile') or {}).get('dataDisks'):
        raise ValidationError('Refusing capture: data disks are not captured or cleaned')
    step('guest agent')
    wait_guest_agent(rg, name)
    step('disc scan')
    lines = guest_task(rg, name, DISC_SCAN_TASK, DISC_SCAN, DISC_SCAN_RESULT, 1500,
                       done=lambda lines: bool(lines) and lines != ['YG_NO_LOG'])
    if lines != ['YG_NO_DISC']:
        # Only fixed status words and numeric counts may reach the public log.
        words = lines[0].split() if lines else []
        status = words[0] if words and words[0] in ('YG_DISC_FOUND', 'YG_SCAN_ERROR') else 'other'
        counts = [v for v in words[1:3] if re.fullmatch(r'[0-9]+', v)]
        print('guest scan: ' + ' '.join([status, *counts]), flush=True)
        raise ValidationError('Refusing capture: guest disc scan did not report a clean disk')
    step('deallocate')
    az('vm', 'deallocate', *rg, '--name', name)
    now = dt.datetime.now(UTC)
    tags = ['owner=agent-image', 'purpose=image', 'source=' + name,
            'run=' + os.environ['GITHUB_RUN_ID'], 'created=' + now.strftime('%Y-%m-%dT%H:%M:%SZ')]
    gallery_args = [*rg, '--gallery-name', GALLERY]
    step('gallery')
    try:
        gallery = az('sig', 'show', *gallery_args)
    except RuntimeError:
        gallery = az('sig', 'create', *gallery_args, '--location', vm['location'], '--tags', *tags)
    az('resource', 'tag', '--ids', gallery['id'], '--tags', *tags)
    definition_args = [*gallery_args, '--gallery-image-definition', image]
    step('image definition')
    try:
        definition = az('sig', 'image-definition', 'show', *definition_args)
    except RuntimeError:
        definition = az('sig', 'image-definition', 'create', *definition_args,
                        '--location', vm['location'], '--os-type', 'Windows',
                        '--os-state', 'Specialized', '--hyper-v-generation', 'V2',
                        '--features', 'SecurityType=Standard', '--publisher', 'yougame',
                        '--offer', 'testbox', '--sku', image, '--tags', *tags)
    az('resource', 'tag', '--ids', definition['id'], '--tags', *tags)
    version = now.strftime('1.%Y%m%d.%H%M%S')
    step('image version')
    az('sig', 'image-version', 'create', *definition_args, '--gallery-image-version', version,
       '--location', vm['location'], '--virtual-machine', vm['id'],
       '--target-regions', vm['location'], '--replica-count', '1',
       '--storage-account-type', 'Standard_LRS', '--tags', *tags)
    step('image retention')
    for old in image_versions(rg, image)[:-2]:
        az('sig', 'image-version', 'delete', *definition_args,
           '--gallery-image-version', old['name'])
    output = {'name': name, 'image': image, 'version': version}
    for k, v in output.items():
        print(k + ': ' + v)
    print('Source box deallocated; run box-down with name: ' + name)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        for k in ('image', 'version'):
            f.write(k + '=' + output[k] + '\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        for k, v in output.items():
            f.write(k + ': ' + v + '\n\n')
        f.write('Source box deallocated; run box-down with name: ' + name + '\n')


def up(inputs):
    image = inputs.get('image', '')
    if image and not re.fullmatch(IMAGE_NAME, image):
        raise ValidationError('Invalid image name')
    key_file = Path('keys/agent-ssh.pub')
    if not image and not key_file.is_file():
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
    os_name = 'image:' + image if image else inputs.get('os', 'windows-2025')
    if not image and os_name not in IMAGES:
        raise ValidationError('Invalid os')
    hours = inputs.get('hours', '2')
    if not re.fullmatch(r'(?:[1-9]|1[0-2])', str(hours)):
        raise ValidationError('hours must be an integer from 1 to 12')
    size, region = inputs.get('size', 'Standard_D2s_v6'), inputs.get('region', 'eastus')
    # Costed sizes only (security-lead 10-31): pay-as-you-go eastus ~$0.04-0.53/h; anything else needs a costed PR.
    if size not in SIZES or not re.fullmatch(r'[a-z0-9]+', region):
        raise ValidationError('Invalid size or region (sizes: ' + ', '.join(sorted(SIZES)) + ')')
    # Keep only key type/base64, never comments identifying its owner. Reject options.
    if not image:
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
    if inputs.get('image_builder') == 'yes':
        tags.append('image_builder=yes')
    rg = ['--resource-group', os.environ['AZURE_RESOURCE_GROUP']]
    common = [*rg, '--location', region, '--tags', *tags]
    # A rerun must never reset/overwrite a live VM's password or SSH configuration.
    if any(r['name'] == name for r in inventory()):
        raise ValidationError('Box already exists; use box-down before retrying')
    if image:
        az('sig', 'image-definition', 'show', *rg, '--gallery-name', GALLERY,
           '--gallery-image-definition', image)
        versions = image_versions(rg, image)
        if not versions:
            raise ValidationError('No image version for ' + image)
        version = versions[-1]
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
                   '--nics', name + '-nic',
                   '--os-disk-name', name + '-os', '--storage-sku', 'Premium_LRS',
                   '--security-type', 'Standard',
                   '--os-disk-delete-option', 'Detach', '--nic-delete-option', 'Detach']
        if image:
            vm_args += ['--image', version['id'], '--specialized']
            step('image ' + image + ' ' + version['name'])
        else:
            vm_args += ['--image', IMAGES[os_name], '--admin-username', ADMIN,
                        '--computer-name', 'ygbox' + os.environ['GITHUB_RUN_ID'][-10:]]
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
    inputs = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()).get('inputs', {})
    if inputs.get('allow_cidr'):
        mask(inputs['allow_cidr'])
        mask(inputs['allow_cidr'].split('/')[0])
    if sys.argv[1] == 'up':
        up(inputs)
    elif sys.argv[1] == 'capture':
        capture(inputs)
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
        print('::error::Test box operation failed (' + type(exc).__name__ + '); details suppressed for public log privacy')
        sys.exit(1)
