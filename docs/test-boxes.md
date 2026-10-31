# Azure agent test boxes

Ephemeral Windows Server 2022 or Ubuntu 24.04 machines for agent network/game tests.
Security has placed the dedicated `keys/agent-ssh.pub` test-boxes public key
and restricted the `test-boxes` GitHub environment to `main`. Keep both prerequisites
in place; the key must be one OpenSSH RSA or Ed25519 public key. No private key belongs
in this repository or on a GitHub runner. The runner fails before login or provisioning
if the public key is missing. Use only trusted workflows on `main`.

The environment supplies **variables**, not secrets: `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`.
Authentication is GitHub OIDC, audience `api://AzureADTokenExchange`, subject
`repo:yougame-co/build:environment:test-boxes`. The identity has Contributor only
on `yougame-test-boxes`; there is no service principal secret.

## Use

Use your own public IPv4 address, followed by `/32`. The workflow cannot verify
that the supplied address belongs to you. Do not use a shared or broad CIDR.

```sh
gh workflow run box-up.yml -R yougame-co/build --ref main \
  -f label=link-test -f allow_cidr=<their-IP>/32
# Optional: -f os=ubuntu-24.04 -f size=Standard_D2s_v5 -f region=eastus -f hours=2
gh run list -R yougame-co/build --workflow box-up.yml
gh run view <run-id> -R yougame-co/build --log
```

Read the four result lines in the log (or the web job summary) for `name`, `public_ip`, `os`, `expires`. These same four
fields are job outputs. The generated Windows password is discarded; use the
dedicated test-boxes private SSH key already provisioned for your agent. Substitute
`ygagent` for `<user>` and the result address for `<ip>`:

```sh
ssh -i ~/.config/yougame-testboxes/agent_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new <user>@<ip>
# When finished:
gh workflow run box-down.yml -R yougame-co/build --ref main -f name=<VM-name>
```

The command accepts a new host key on first connection and rejects changed keys.
Verify the first fingerprint through a trusted Azure management session if needed.
Never use `-A` (agent forwarding), never copy the dedicated key file, and never
upload an SSH private key to a VM. A box that must reach another box gets its own
throwaway key; destroy that key with the box. Windows SSH accepts only the repository public
key via `administrators_authorized_keys`, with SYSTEM/Administrators ACLs and
public key authentication only. Ubuntu uses Azure's SSH-only provisioning.
TCP 22 and UDP 51600-51699 are the only allowed NSG inbound traffic, exclusively
from the supplied `/32`; an explicit deny overrides default VNet/load-balancer
allow rules. Windows also enables the UDP range in the guest firewall. The
Ubuntu image has no additional workflow-managed guest firewall rules.

Names are `ygbox-<label>-<run-id>`. Labels are 1-32 lowercase letters, numbers or
hyphens with alphanumeric ends. A rerun cannot overwrite an existing box; tear
it down first. GPU sizes are accepted, but fail until the subscription has quota
and the requested region has capacity. A D2s_v5 is suitable for basic networking (B-series is capacity-blocked in eastus for this account, 10-31);
GPU/game performance is a separate capacity decision. VMs explicitly use the
Standard security type for compatibility with the default D2s_v5 size.

Lifetime is 1-12 whole hours (default 2). The hourly reaper runs at minute 17,
deleting expired `owner=agent` resources and resources at least 12 hours old,
regardless of an extended expiry. Invalid or missing lifecycle timestamps cause
cleanup as well. GitHub scheduled jobs may be delayed; expiry is not an exact
shutdown time and the budget is an alert, not a spending cap. Delete promptly.
You can dispatch `box-reaper.yml` manually to retry cleanup. `box-down` requires
an existing VM with `owner=agent`; use the reaper for orphaned partial creates.

VM, NIC, OS disk, public IP, NSG and a dedicated VNet are cleaned up. All names
are derived from the VM, with shared owner/purpose/expiry/run/box/created tags.
Azure creates the OS disk during VM creation; it is tagged immediately afterward.
Cleanup can recover that untagged disk after a runner cancellation using its
exact `<box>-os` name and an independently tagged box resource. Failed setup
attempts cleanup immediately. If cleanup fails or a runner times out, the reaper
retries. Review any failed cleanup run.

## Public logs and data

This is a public repo. Scripts mask the supplied address and CIDR, admin user,
generated Windows password, OIDC bearer and federated token before use. Azure
stdout/stderr is captured and suppressed, including Run Command output. No
artifacts are uploaded. Summary/output fields contain only VM name, VM public
IP, OS and expiry; reaper/deletion messages contain resource names only.

Masking protects runner logs, **not GitHub's dispatch input metadata**. Do not
put secrets in inputs; `allow_cidr` necessarily gives the caller address to
GitHub and Azure. There is no claim that dispatch metadata is private.

Agents never put game discs, ROMs or keys on a box except when a test needs the
team copy. That copy stays inside the VM and dies with it. Never route it through
this repository, GitHub runners, logs, summaries or artifacts; never export it
from the box. Delete the VM and its OS disk when the test ends.

## Cost

Microsoft's [Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
was queried on 2026-10-31 with `serviceName eq 'Virtual Machines' and
armRegionName eq 'eastus' and armSkuName eq 'Standard_B2s' and
priceType eq 'Consumption'`, selecting the regular `B2s` SKU (no Spot/Low Priority).
The returned USD pay-as-you-go compute rates, per hour, were:

| OS | Size | East US USD/hour | Default 2-hour compute |
| --- | --- | ---: | ---: |
| Ubuntu 24.04 | Standard_B2s | $0.0416 | $0.0832 |
| Windows Server 2022 | Standard_B2s | $0.0496 | $0.0992 |

Rates exclude the Standard HDD OS disk, Standard public IPv4, egress and taxes;
these can keep accruing until resources are deleted. Other regions/sizes cost
more or less. The resource group has a $200/month budget with alerts. Check
[Azure pricing](https://azure.microsoft.com/en-us/pricing/calculator/) before
requesting a larger or GPU machine.

Allowed sizes (10-31, eastus capacity): Standard_D2s_v5, Standard_D4s_v5 (Windows/Linux x64), Standard_D4ps_v5 (ARM), Standard_NC4as_T4_v3 (GPU, needs quota). The B2s price table above is history; check current prices before a long run.
