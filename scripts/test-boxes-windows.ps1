$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Runs through the Custom Script Extension as SYSTEM. Every step is a fixed line on stdout (box-up prints them) and
# in C:\yg\ssh-setup.log, so a failure names its step.
$log = 'C:\yg\ssh-setup.log'
$started = Get-Date
$current = 'start'
function Step($name) {
    $script:current = $name
    $line = '[+{0}s] {1}' -f [int]((Get-Date) - $started).TotalSeconds, $name
    Add-Content -Path $log -Encoding ascii -Value $line
    Write-Output $line
}
try {
    Step 'start'
    # Server 2025 ships sshd in the OS. Querying the Feature on Demand there can wait on Windows Update, so only an
    # image without sshd asks DISM.
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        Step 'openssh capability'
        $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        if ($capability.State -ne 'Installed') {
            Step 'openssh install'
            Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
        }
    }
    # Generate host keys without starting the service with default authentication. On a fresh image sshd has
    # never run, so its ProgramData folder may not exist yet; private host keys get SYSTEM/Administrators-only ACLs.
    Step 'host keys'
    New-Item -ItemType Directory -Force -Path 'C:\ProgramData\ssh' | Out-Null
    & "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -A | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SSH host key generation failed' }
    foreach ($hostKey in Get-ChildItem 'C:\ProgramData\ssh\ssh_host_*_key') {
        & icacls.exe $hostKey.FullName /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SSH host key ACL configuration failed' }
    }
    Step 'authorized key'
    $keyFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
    Set-Content -Path $keyFile -Value '__PUBLIC_KEY__' -Encoding ascii
    & icacls.exe $keyFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SSH key ACL configuration failed' }
    # A complete config removes alternate key sources, password/interactive auth,
    # forwarding and the default per-user authorized_keys file.
    Step 'sshd config'
    @'
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile C:/ProgramData/ssh/administrators_authorized_keys
AllowUsers ygagent
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
Subsystem sftp sftp-server.exe
'@ | Set-Content -Path 'C:\ProgramData\ssh\sshd_config' -Encoding ascii
    & "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
    if ($LASTEXITCODE -ne 0) { throw 'SSH configuration validation failed' }
    Step 'firewall'
    if (-not (Get-NetFirewallRule -Name 'YouGame-SSH' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'YouGame-SSH' -DisplayName 'YouGame SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
    }
    if (-not (Get-NetFirewallRule -Name 'YouGame-Link' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'YouGame-Link' -DisplayName 'YouGame Link' -Direction Inbound -Protocol UDP -LocalPort 51600-51699 -Action Allow | Out-Null
    }
    Step 'start sshd'
    Set-Service sshd -StartupType Automatic
    Start-Service sshd
    if ((Get-Service sshd).Status -ne 'Running') { throw 'SSH did not start' }
    Add-Content -Path $log -Encoding ascii -Value 'YG_SSH_READY'
    Write-Output 'YG_SSH_READY'
} catch {
    # Only the step name: exception text can carry paths or addresses and the log is public.
    Add-Content -Path $log -Encoding ascii -Value ('YG_FAIL ' + $current)
    Write-Output ('YG_FAIL ' + $current)
}
