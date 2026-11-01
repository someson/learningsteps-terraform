# LearningSteps — Base Deployment

A one-command Azure deployment of the [LearningSteps](https://github.com/CyberstepsDE/learningsteps) API and a PostgreSQL database.

For the walkthrough built on top of this deployment, see [handbook.md](handbook.md).

**Security hardening documentation:** see [Security Hardening](#security-hardening) below. All documents live in [`security/`](security/).

> **This deployment is intentionally minimal and unsecured.** The VM is publicly reachable, the database accepts connections from any IP, credentials are stored in plaintext, and there is no traffic inspection or monitoring. It is a starting point — not a production setup.

## What Gets Deployed

- **Ubuntu VM** (Standard_D2s_v6 by default, configurable via `vm_size`) running the FastAPI application on port 8000
- **Azure PostgreSQL Flexible Server** (B1ms) as the database
- A virtual network with one subnet and a basic network security group

## Security Hardening

This project documents how the intentionally insecure "Base Deployment" is
turned into a hardened, production-ready architecture: what was wrong, what
was changed, how, and how the fix was verified.

### Documents

| # | Document | Status |
|---|---|---|
| — | [Walkthrough log](security/walkthrough-log.md): every command run, problems hit and how they were fixed | 🔄 ongoing |
| 00 | [Baseline security assessment](security/00-baseline-assessment.md): threat model, findings F-01…F-17, roadmap | ✅ done |
| 01 | [Day 1: Management access](security/01-management-access.md) (Entra ID SSH, SSH restricted to a trusted IP) | ✅ done, verified |
| 02 | [Day 2: TLS + Web Application Firewall](security/02-tls-waf.md) (NPMplus, Let's Encrypt, CrowdSec/CRS) | ✅ done, verified |
| 03 | [Day 3: Identity-based API access](security/03-identity-api-access.md) (Entra ID + oauth2-proxy) | ✅ done, verified |
| 04 | Day 4: Data isolation (PostgreSQL VNet integration, private DNS) | ⏳ |
| 05 | Day 5: Detection and response (Sentinel + auto-block playbook) | ⏳ |

### Structure of each day's document

1. **Problem**: which findings from [`security/00-baseline-assessment.md`](security/00-baseline-assessment.md) it addresses
2. **Threat**: how an attacker exploits it
3. **Change**: code diff (Terraform / scripts) or manual steps, with the reason for each
4. **Verification**: before/after commands and their output (e.g. `curl`, `psql`, `nmap`)
5. **Residual risk**: what is still not covered and how the managed Azure service would do it (Bastion, Application Gateway WAF, Key Vault, Private Endpoint, Defender for Cloud)

### Findings tracker

| ID | Short name | Severity | Fixed in |
|---|---|---|---|
| F-01 | SSH open to the internet | High | Day 1 |
| F-02 | Static SSH key only | Medium | Day 1 (partially: key still exists) |
| F-03 | Public DB, firewall allows all IPs | Critical | |
| F-04 | VM→DB over the public internet | High | |
| F-05 | API without authentication | Critical | Day 3 (authentication; no per-action authorization yet) |
| F-06 | No TLS | High | Day 2 |
| F-07 | No WAF | High | Day 2 |
| F-08 | API bound to 0.0.0.0 at boot | Medium | |
| F-09 | DB password in plaintext (state, custom_data, unit file) | High | |
| F-10 | App uses DB admin account | Medium | |
| F-11 | Default NPMplus admin credentials | High | Day 2 (password changed; default still in script) |
| F-12 | SSH host key verification disabled in deploy.py | Low | |
| F-13 | Unpinned images / dependencies | Low–Medium | |
| F-14 | No detection / response | Medium | |
| F-15 | Local unencrypted Terraform state | Medium | |
| F-16 | Flat network, VM with public IP | Medium | |
| F-17 | oauth2-proxy allows any tenant user | Low–Medium | |

## Prerequisites

Install the following before running the script:

| Tool | Install |
|---|---|
| Python 3.8+ | [python.org](https://www.python.org/downloads/) — on Windows use `python`, on macOS/Linux use `python3` |
| Terraform ≥ 1.5 | [developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install) |
| Azure CLI | [learn.microsoft.com/en-us/cli/azure/install-azure-cli](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| Azure CLI `ssh` extension | `az extension add --name ssh` — required for the handbook's `az ssh` / `az ssh config` commands (Entra ID VM login) |
| Azure subscription | Your account needs **Contributor** or **Owner** role on the subscription |

## Deploy

```bash
python3 deploy.py
```

On Windows:
```
python deploy.py
```

The script will:
1. Log you in to Azure if needed (opens a browser)
2. Generate an SSH key pair in the project folder
3. Ask for a resource prefix and Azure region (IMPORTANT - Make sure your prefix is unique and includes your name, otherwise the deployment will fail due to naming conflicts)
4. Ask for a PostgreSQL admin password
5. Run `terraform apply` — takes about 7–8 minutes
6. Run a smoke test against the deployed API

To skip the interactive prompts:
```bash
python3 deploy.py --password YourPassword1 --prefix learningstepsbob --location westeurope
```

Once deployed, the script prints the API URL and SSH command.

## Stopping and Starting

When not in use, deallocate the VM to avoid compute charges:
```bash
az vm deallocate --resource-group rg-<prefix> --name vm-<prefix>
```

Start it again:
```bash
az vm start --resource-group rg-<prefix> --name vm-<prefix>
```

Stop the database:
```bash
az postgres flexible-server stop --resource-group rg-<prefix> --name psql-<prefix>
```

Start it again:
```bash
az postgres flexible-server start --resource-group rg-<prefix> --name psql-<prefix>
```

> Note: Azure automatically restarts a stopped PostgreSQL Flexible Server after 7 days.

To destroy everything permanently:
```bash
terraform destroy
```

## Troubleshooting

- **`terraform apply` fails with a Sentinel-related resource "already
  exists"** (seen on `azurerm_sentinel_log_analytics_workspace_onboarding.main`,
  `azurerm_sentinel_alert_rule_scheduled.waf_attack`, and
  `azurerm_sentinel_automation_rule.block_attacker`) — happens if you
  `terraform destroy` and then redeploy with the *same prefix* shortly after:
  these Sentinel objects use fixed names (not random IDs) and can take a few
  minutes to clear on Azure's side even though the Log Analytics workspace
  itself is gone. `terraform apply` fails on the first one it hits — expect
  to repeat this for each one in turn (apply, hit next conflict, import,
  re-apply) rather than all three appearing in one error. Fix each by
  importing it into the new state, then re-running apply:
  ```bash
  az account show --query id -o tsv   # get your subscription ID

  terraform import azurerm_sentinel_log_analytics_workspace_onboarding.main \
    "/subscriptions/<subscription-id>/resourceGroups/rg-<prefix>/providers/Microsoft.OperationalInsights/workspaces/law-<prefix>/providers/Microsoft.SecurityInsights/onboardingStates/default"

  terraform import azurerm_sentinel_alert_rule_scheduled.waf_attack \
    "/subscriptions/<subscription-id>/resourceGroups/rg-<prefix>/providers/Microsoft.OperationalInsights/workspaces/law-<prefix>/providers/Microsoft.SecurityInsights/alertRules/waf-attack-scheduled"

  terraform import azurerm_sentinel_automation_rule.block_attacker \
    "/subscriptions/<subscription-id>/resourceGroups/rg-<prefix>/providers/Microsoft.OperationalInsights/workspaces/law-<prefix>/providers/Microsoft.SecurityInsights/automationRules/a1b2c3d4-0000-0000-0000-000000000001"

  terraform apply
  ```
  Avoiding it entirely: use a different prefix, or wait a few minutes after
  destroy before reusing the same one.

- **`SkuNotAvailable` for the VM size** — Azure has no capacity for that
  size in the region right now. Pick another 2-vCPU size that is available:
  ```bash
  az vm list-skus --location westeurope --resource-type virtualMachines \
    --query "[?contains(name,'_D2') && restrictions==\`[]\`].name" -o tsv | sort -u
  ```
  and set it in `terraform.tfvars`, e.g. `vm_size = "Standard_D2as_v5"`.
  `*_v6` sizes automatically get `disk_controller_type = "NVMe"` (`vm.tf`).

## SSH Access

The SSH key is generated in the project folder during deployment:

```bash
ssh azureuser@<vm-ip> -i .learningsteps_key
```

