# LearningSteps — Base Deployment

A one-command Azure deployment of the [LearningSteps](https://github.com/CyberstepsDE/learningsteps) API and a PostgreSQL database.

For the walkthrough built on top of this deployment, see [handbook.md](handbook.md).

**Security hardening documentation:** see [security/](security/README.md). Start with the [baseline security assessment](security/00-baseline-assessment.md).

> **This deployment is intentionally minimal and unsecured.** The VM is publicly reachable, the database accepts connections from any IP, credentials are stored in plaintext, and there is no traffic inspection or monitoring. It is a starting point — not a production setup.

## What Gets Deployed

- **Ubuntu VM** (Standard_D2s_v6 by default, configurable via `vm_size`) running the FastAPI application on port 8000
- **Azure PostgreSQL Flexible Server** (B1ms) as the database
- A virtual network with one subnet and a basic network security group

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

