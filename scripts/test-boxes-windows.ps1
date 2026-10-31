$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
# Generate host keys without starting the service with default authentication.
& "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -A
if ($LASTEXITCODE -ne 0) { throw 'SSH host key generation failed' }
$keyFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -Path $keyFile -Value '__PUBLIC_KEY__' -Encoding ascii
& icacls.exe $keyFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SSH key ACL configuration failed' }
# A complete config removes alternate key sources, password/interactive auth,
# forwarding and the default per-user authorized_keys file.
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
if (-not (Get-NetFirewallRule -Name 'YouGame-SSH' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'YouGame-SSH' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
}
New-NetFirewallRule -Name 'YouGame-Link' -Direction Inbound -Protocol UDP -LocalPort 51600-51699 -Action Allow | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
if ((Get-Service sshd).Status -ne 'Running') { throw 'SSH did not start' }
Write-Output 'YG_SSH_READY'
