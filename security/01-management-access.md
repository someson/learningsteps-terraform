# 01 — Day 1: Locking Down Management Access

**Findings addressed:** F-01 (SSH open to the internet), F-02 (static SSH key only).

## Problem and threat

At baseline the NSG rule `allow-ssh` had `source_address_prefix = "*"`, so
every host on the internet could reach port 22. Internet-facing SSH gets
automated brute-force and key-spraying attempts within minutes of a VM
getting a public IP. Access itself relied on one static private key file
(`.learningsteps_key`). Anyone who copies that file gets root-capable access,
there is no MFA, and logs show only "azureuser" — not *which person* logged in.

## Changes

| File | Change | Why |
|---|---|---|
| `variables.tf` | New required variable `admin_source_ip`, validated to be an IPv4 address/CIDR; `*` and IPv6 are rejected | Makes "open to everyone" impossible to configure by accident. IPv6 is rejected because the VM's public IP is IPv4-only — an IPv6 source would lock the operator out |
| `network.tf` | `allow-ssh` now uses `source_address_prefix = var.admin_source_ip` | Network layer: only the trusted IP can even open a TCP connection to 22 |
| `vm.tf` | New `azurerm_role_assignment.vm_admin_login` — role **Virtual Machine Administrator Login**, scoped to the VM, for the identity running Terraform | Identity layer: enables `az ssh vm` with Entra ID (short-lived certificate, MFA/Conditional Access apply, logins are attributable to a person). Scoped to one VM = least privilege. Subscription Owner does **not** imply OS login — this has to be granted explicitly |
| `deploy.py` | Detects the operator's public IPv4 and writes `admin_source_ip` to `terraform.tfvars` (also adds it to an existing tfvars) | Secure by default with zero extra manual steps |
| `terraform.tfvars.example` | Documents `admin_source_ip` | |

Already present at baseline and now actually used: system-assigned managed
identity on the VM and the `AADSSHLoginForLinux` extension (`vm.tf`).

## How to apply

```bash
curl -s -4 ifconfig.me                 # your public IPv4
# add to terraform.tfvars:  admin_source_ip = "<that IP>"
terraform apply                        # NSG update + role assignment, < 1 min
```

## Verification

```bash
# 1. Entra ID login works without the key file
az ssh vm --resource-group rg-<prefix> --name vm-<prefix>

# 2. The role is assigned, scoped to the VM
VM_ID=$(az vm show -g rg-<prefix> -n vm-<prefix> --query id -o tsv)
az role assignment list --scope "$VM_ID" --role "Virtual Machine Administrator Login" -o table

# 3. The NSG rule is no longer open to the internet
az network nsg rule show -g rg-<prefix> --nsg-name nsg-app -n allow-ssh \
  --query "{source:sourceAddressPrefix, port:destinationPortRange}" -o table

# 4. From any other IP (e.g. phone hotspot / Azure Cloud Shell) — connection times out
ssh -o ConnectTimeout=5 azureuser@<vm-ip>
```

| Check | Before | After |
|---|---|---|
| `allow-ssh` source | `*` | `<my-ip>/32` |
| SSH from another IP | login prompt | timeout |
| `az ssh vm` | `AuthorizationFailed` | shell as my Entra user |

<!-- TODO: paste real command output / screenshots here -->

## Residual risk

- The static key still exists and still works from the trusted IP (`deploy.py`
  uses it for automation). Next step: remove it after setup, or disable
  password+key auth and keep Entra ID only.
- A home IP can change (dynamic IP) → you need to update `admin_source_ip`
  and re-apply.
- Port 22 is still reachable on the internet from the trusted IP. Managed
  alternatives: **Azure Bastion** (no public IP on the VM at all) or
  **Just-In-Time VM access** (Defender for Cloud opens 22 only on request and
  only for a limited time).
