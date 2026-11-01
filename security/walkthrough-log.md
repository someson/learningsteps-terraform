# Walkthrough Log

A chronological record of what was actually run, what went wrong, and how it
was fixed. It complements the per-day documents (`01-…`, `02-…`), which
describe *what* was hardened and *why*. This log records *how it went in
practice*.

Environment: macOS (Apple Silicon), Python 3.14.6, Terraform 1.16.2,
Azure CLI 2.89.1. Resource prefix `ls-vladi`, region `westeurope`.
Secrets (DB password, subscription ID) are redacted throughout.

---

## Step 0 — Repository workflow

- Working repository: `someson/learningsteps-terraform`, a **fork** of
  `CyberstepsDE/learningsteps-terraform`.
- Every change lives on its own branch `day/<what-it-does>`. It is merged into
  `main` through a pull request, so the PR history documents the project day
  by day.

### Problem: the PR target defaults to the upstream course repository
When a PR is opened from the GitHub web UI in a fork, **base repository**
defaults to `CyberstepsDE/learningsteps-terraform`. Clicking "Create pull
request" would have sent the change to the course maintainers.

**Fix:** always switch *base repository* to `someson/learningsteps-terraform`
before creating a PR. Alternatively, run this once inside the clone so that
`gh pr create` targets the fork:
```bash
gh repo set-default someson/learningsteps-terraform
```

---

## Step 1 — Prerequisites check

```bash
python3 --version     # Python 3.14.6
terraform -version    # Terraform v1.16.2 (the "out of date" notice is harmless)
az version            # azure-cli 2.89.1; the ssh extension was missing
```
The `ssh` extension for `az` was not installed. `deploy.py` installs it
automatically (`az extension add --name ssh`).

---

## Step 2 — Baseline deployment (attempt 1): failed

```bash
git clone https://github.com/someson/learningsteps-terraform
cd learningsteps-terraform
python3 deploy.py --prefix ls-vladi --location westeurope
```

The network, PostgreSQL server and firewall rule were created. The VM failed:

```
Error: creating Linux Virtual Machine ... unexpected status 409 (409 Conflict)
with error: SkuNotAvailable: The requested VM size ... Standard_D2s_v3 is
currently not available in location 'westeurope'.
  on vm.tf line 23, in resource "azurerm_linux_virtual_machine" "vm"
```

**Root cause:** the VM size was hard-coded to `Standard_D2s_v3`, and Azure had
no capacity for that size in West Europe (a capacity restriction, not a
quota or code error).

**Fix:** PR #2, branch `day/0-fix-vm-size`.
- New variable `vm_size` (default `Standard_D2s_v6`, same 2 vCPU / 8 GB).
- v6 sizes support **only the NVMe disk controller**. With only the size
  changed, Azure rejects the VM because Terraform defaults to SCSI. So
  `disk_controller_type` is derived from the size: `NVMe` for `*_v6`, `SCSI`
  otherwise.
- The README troubleshooting section shows how to list sizes that are
  available in a region:
  ```bash
  az vm list-skus --location westeurope --resource-type virtualMachines \
    --query "[?contains(name,'_D2') && restrictions==\`[]\`].name" -o tsv | sort -u
  ```

**Lesson:** never hard-code capacity-dependent values. Make them variables
with a sensible default.

---

## Step 3 — Baseline deployment (attempt 2): partial success

```bash
git pull origin main          # after merging PR #3 + PR #4 (see note below)
python3 deploy.py             # "Reuse terraform.tfvars? [Y/n]" -> Y
```

Note: the branches were stacked (`main` → `day/0-fix-vm-size` →
`day/0-baseline-assessment` → `day/1-restrict-management-access`). Merging
PR #3 and PR #4 at 17:35 UTC brought **all three commits** into `main`: the VM
size fix, the documentation and the Day 1 code. So this run already deployed
the Day 1 hardening (see Step 4).

Terraform kept the resources that already existed and created only the VM
and its dependants. The API, smoke tests, seeding, oauth2-proxy install and
the log forwarder all succeeded. One step failed:

```
1 check(s) failed:
  - NPMplus/CrowdSec setup failed (exit 100): E: Could not get lock
    /var/lib/dpkg/lock-frontend. It is held by ...
```

**Root cause:** a race condition. `deploy.py` started
`scripts/setup-npmplus.sh` (which runs `apt-get install docker-ce …`) while
the freshly booted VM was still running its own package operations
(cloud-init / unattended-upgrades). Ubuntu allows only one dpkg process at a
time, so the second one fails immediately instead of waiting.

**Fix (manual, applied):** wait until cloud-init has finished and the dpkg
lock is free, then re-run the idempotent setup script:

```bash
VM_IP=$(terraform output -raw vm_public_ip)

ssh -i .learningsteps_key azureuser@$VM_IP \
  "sudo cloud-init status --wait; \
   while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1; do sleep 5; done; \
   echo apt free"

ssh -i .learningsteps_key azureuser@$VM_IP "sudo bash -s" < scripts/setup-npmplus.sh
```

Verification:
```bash
ssh -i .learningsteps_key azureuser@$VM_IP "sudo docker ps --format '{{.Names}}: {{.Status}}'"
# crowdsec: Up About a minute
# npmplus: Up About a minute (healthy)
```

**Permanent fix (proposed):** make `setup-npmplus.sh` wait for the dpkg lock
(`cloud-init status --wait` plus `apt-get -o DPkg::Lock::Timeout=600`)
instead of failing.

**Result:** the baseline is fully deployed (VM, PostgreSQL, NPMplus,
CrowdSec, oauth2-proxy installed but not started, Sentinel pipeline).

---

## Step 4 — Day 1: Management access ✅

Details and rationale: [01-management-access.md](01-management-access.md).

### 4.1 Initial check (expected "before", turned out to be "after")

Expected baseline state: `allow-ssh` source `*`, and `az ssh vm` fails
because the user has no "Virtual Machine Administrator Login" role.
**Actual state (2026-11-01, 17:53 UTC) differed from that:**

```text
❯ az network nsg rule show -g rg-ls-vladi --nsg-name nsg-app -n allow-ssh \
    --query "{source:sourceAddressPrefix, port:destinationPortRange}" -o table
Source         Port
-------------  ------
91.38.119.x    22
```
The SSH rule was already restricted to a single IP, not `*`.

```text
❯ az ssh vm -g rg-ls-vladi -n vm-ls-vladi
On May 21st 2025, any ssh commands connecting to ARC machines on versions <2.0.4 will no longer work. Please upgrade to az ssh version >=2.0.4
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1070-azure x86_64)
  ...
  System information as of Sun Nov  1 17:53:23 UTC 2026
  IPv4 address for eth0: 10.0.1.4
  ...
4 updates can be applied immediately.
3 of these updates are standard security updates.
  ...
New release '24.04.5 LTS' available.
```
Entra ID login already succeeded.

Side observations (inputs for later hardening):
- `3 standard security updates` are pending on a VM that is minutes old.
  Patch management is missing (relates to F-13).
- The `az ssh` extension warns that it is outdated (`< 2.0.4`). Fix with
  `az extension update --name ssh`.

Identity check inside that session:
```text
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com@vm-ls-vladi:~$ whoami
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com@vm-ls-vladi:~$ exit
logout
Connection to 20.101.139.95 closed.
```
The OS user is the **Entra ID identity** (UPN), not the local `azureuser`
account. This shows that `AADSSHLoginForLinux` + RBAC login works and that
the session is attributable to a named person.

**Open question, being investigated:** who changed the NSG rule, and where
the VM login role comes from (subscription/RG-level assignment, or done
earlier by hand). Evidence to collect:
```bash
# inside the VM: which identity am I logged in as?
whoami
# role assignments for my user, at any scope
az role assignment list --assignee "$(az ad signed-in-user show --query id -o tsv)" --all \
  --query "[?contains(roleDefinitionName,'Virtual Machine')].{role:roleDefinitionName, scope:scope}" -o table
# who modified NSG rules and when (Azure Activity Log, last 7 days)
az monitor activity-log list -g rg-ls-vladi --offset 7d \
  --query "[?contains(operationName.value,'securityRules/write')].{time:eventTimestamp, caller:caller, status:status.value}" -o table
```
Results:
```text
❯ az role assignment list --assignee "$(az ad signed-in-user show --query id -o tsv)" --all \
    --query "[?contains(roleDefinitionName,'Virtual Machine')].{role:roleDefinitionName, scope:scope}" -o table
Role                                 Scope
-----------------------------------  ----------------------------------------------------------------------------------------------------------
Virtual Machine Administrator Login  /subscriptions/<sub-id>/resourceGroups/rg-ls-vladi/providers/Microsoft.Compute/virtualMachines/vm-ls-vladi

❯ az monitor activity-log list -g rg-ls-vladi --offset 7d \
    --query "[?contains(operationName.value,'securityRules/write')]..." -o table
(empty)

❯ curl -s -4 ifconfig.me
91.38.119.x        # identical to the IP in the allow-ssh rule
```

Further evidence:
```text
❯ az role assignment list --assignee "$(az ad signed-in-user show --query id -o tsv)" \
    --scope "$(az vm show -g rg-ls-vladi -n vm-ls-vladi --query id -o tsv)" \
    --query "[].{created:createdOn, createdBy:createdBy}" -o table
Created                           CreatedBy
--------------------------------  ------------------------------------
2026-11-01T17:42:55.575948+00:00  5d034241-9db7-4e91-a21c-1c699a622361

❯ terraform state list | grep -E "role_assignment|network_security_group"
azurerm_network_security_group.app
azurerm_role_assignment.playbook_network_contributor
azurerm_role_assignment.playbook_sentinel_responder
azurerm_role_assignment.sentinel_can_trigger_playbook
azurerm_role_assignment.vm_admin_login          # <- Day 1 resource, managed by Terraform
azurerm_role_assignment.vm_ama_publisher
azurerm_subnet_network_security_group_association.app
```

**Conclusion:** nothing was changed by hand. The first hypothesis was manual
changes, i.e. configuration drift, which would have required
`terraform import`. That turned out to be **wrong**. The timeline:

| Time (UTC) | Event |
|---|---|
| ~16:xx | Attempt 1 (original code) creates `nsg-app` with `allow-ssh` source **`*`**, then fails on the VM |
| 17:35 | PR #3 + PR #4 merged. `main` now contains the Day 1 code |
| 17:42 | Attempt 2: `deploy.py` auto-detects the operator IPv4 and writes `admin_source_ip`. Terraform updates `allow-ssh` to that IP and creates `azurerm_role_assignment.vm_admin_login` (`createdOn` 17:42:55) |

So the Day 1 hardening was applied **by code, during deployment**: secure by
default. The role is scoped to the single VM (least privilege).

The activity-log query for `networkSecurityGroups/write` also returned
nothing. Note for the future: inline NSG rules are logged as NSG writes, not
as `securityRules/write`.

### 4.2 Verification "after"
```bash
terraform plan
# expected: No changes. Your infrastructure matches the configuration.

# from a DIFFERENT IP (Azure Cloud Shell):
timeout 10 bash -c "</dev/tcp/20.101.139.95/22" && echo OPEN || echo "BLOCKED (timeout)"
# expected: BLOCKED (timeout)

# from the trusted IP (operator Mac):
nc -vz -w 5 20.101.139.95 22
# expected: succeeded
```
Actual `terraform plan` result:
```text
Plan: 0 to add, 12 to change, 0 to destroy.
```
All 12 changes are **noise, not security-relevant**. None of them touches
`allow-ssh` or `vm_admin_login`, which confirms the Day 1 state matches the code:

| Diff | Resources | Cause |
|---|---|---|
| `tags: - "created-on" = "2026-11-01T17:4x…" -> null` | 11 (RG, VNet, NSG, NIC, PIP, VM, PostgreSQL, LAW, DCR, 2 VM extensions) | A tag added by Azure itself (most likely an **Azure Policy** in the course tenant that stamps every new resource) and unknown to Terraform. Applying would remove it, the policy would re-add it, and the plan would never be clean |
| `vm_agent_platform_updates_enabled = true -> false` | VM | Azure enables it server-side, while the azurerm 3.x provider defaults to `false` |
| `parameters_content`: `nsgName` → `NsgName`, `"String"` → `"string"` | ARM template deployment (playbook) | Azure normalises casing in the stored deployment, so the template text and the stored copy never match byte-for-byte |

**Decision:** do **not** run `terraform apply` for this. It would change nothing
meaningful and the diff would come back.

**Why it still matters for security:** a noisy plan hides real drift. If
someone opened SSH to `*` by hand, that line would get lost among 12 harmless
ones. Fix (proposed): `lifecycle { ignore_changes = [...] }` for exactly these
attributes, so that `terraform plan` shows "No changes" and any future diff is
a real signal.

**Fix applied:** branch `day/1-clean-terraform-plan` (commit `ddaf165`),
merged into `main`.
- `lifecycle { ignore_changes = [tags["created-on"]] }` on the 11 affected
  resources. **Only this one key** is ignored, all other tags are still
  compared.
- VM: `ignore_changes` also for `vm_agent_platform_updates_enabled`.
- Playbook ARM template: **fixed instead of ignored**. Parameter names and
  types now use the form Azure stores (`playbookName`/`nsgName`, `"String"`).
  The inner Logic App parameter `NsgName` is a different object and was not
  renamed.

```bash
git checkout main && git pull origin main
terraform plan
```
```text
  # azurerm_resource_group_template_deployment.block_ip_playbook will be updated in-place
      ~ template_content = jsonencode(
              ~ parameters = {
                  - NsgName      = { - type = "String" }
                  - PlaybookName = { - type = "String" }
                  + nsgName      = { + type = "String" }
                  + playbookName = { + type = "String" }
                }
              ~ name = "[parameters('PlaybookName')]" -> "[parameters('playbookName')]"
              ~ defaultValue = "[parameters('NsgName')]" -> "[parameters('nsgName')]"
              ...
Plan: 0 to add, 1 to change, 0 to destroy.
```
As expected: the tag and VM-agent noise is gone (11 of 12 diffs). The one
remaining change is the one-time redeploy of the renamed template.

```bash
terraform apply
terraform plan     # expected: No changes. Your infrastructure matches the configuration.
```
```text
❯ terraform apply
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

❯ terraform plan
No changes. Your infrastructure matches the configuration.
```
**Result:** the plan is clean. From now on, any diff in `terraform plan`
is a real signal (manual change or drift), not noise.

Remaining checks:
From the trusted IP (operator Mac):
```text
❯ nc -vz -w 5 20.101.139.95 22
Connection to 20.101.139.95 port 22 [tcp/ssh] succeeded!
```

From a different IP (Azure Cloud Shell):
```text
volodymyr [ ~ ]$ timeout 10 bash -c "</dev/tcp/20.101.139.95/22" && echo OPEN || echo "BLOCKED (timeout)"
BLOCKED (timeout)
```

**Day 1 result: done and verified.**
- SSH (22) is reachable only from the trusted IP. Any other source (Cloud
  Shell) gets no TCP connection at all, because the NSG drops it before it
  reaches the VM.
- Interactive login uses the Entra ID identity
  (`volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com`), not the
  shared `azureuser` key.
- `terraform plan` is clean, so the hardened state is exactly what the code
  describes.

---

## Step 5 — Day 2: TLS + Web Application Firewall ✅

### 5.1 Entra ID SSH config for tunnels
`az ssh vm` cannot forward ports (`-L`). `az ssh config` writes an OpenSSH
config file wired to a short-lived Entra ID certificate, and plain `ssh -F`
can then tunnel through it.

```text
❯ az ssh config --resource-group rg-ls-vladi --name vm-ls-vladi --file azssh_config
On May 21st 2025, any ssh commands connecting to ARC machines on versions <2.0.4 will no longer work. Please upgrade to az ssh version >=2.0.4
Generated SSH certificate .../learningsteps-terraform/az_ssh_config/rg-ls-vladi-vm-ls-vladi/id_rsa.pub-aadcert.pub is valid until 2026-11-01 08:27:55 PM in local time.
.../learningsteps-terraform/az_ssh_config/rg-ls-vladi-vm-ls-vladi contains sensitive information (id_rsa, id_rsa.pub, id_rsa.pub-aadcert.pub). Please delete it once you no longer need this config file.
```

Observations:
- The certificate is **short-lived** (about 1 hour). This is a security
  benefit over the static key: a leaked certificate expires on its own.
  After expiry, re-run `az ssh config`.
- **Security finding (new):** the command writes a **private key**
  (`az_ssh_config/.../id_rsa`) and `azssh_config` **inside the repository
  folder**, and `.gitignore` does not exclude them. A careless `git add .`
  would publish a private key. Fix: add `azssh_config` and `az_ssh_config/`
  to `.gitignore`, and delete the folder after use.

### 5.2 SSH tunnel (app :8000, NPMplus admin :81)
```text
❯ ssh -F azssh_config -L 8000:localhost:8000 -L 8081:localhost:81 20.101.139.95
bind [127.0.0.1]:8081: Address already in use
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1070-azure x86_64)
  ...
Last login: Sun Nov  1 17:53:23 2026 from 91.38.119.x
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com@vm-ls-vladi:~$
```
**Problem:** local port 8081 on the Mac was already taken by another
program, so only the 8000 tunnel came up. SSH still logs in and only prints
a warning, which is easy to miss.
**Fix:** use a free local port for the admin tunnel (`-L 18081:localhost:81`).
```text
❯ ssh -F azssh_config -L 8000:localhost:8000 -L 18081:localhost:81 20.101.139.95
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1070-azure x86_64)
  ...
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com@vm-ls-vladi:~$
```
Both tunnels are up (no bind error). The app is at `http://localhost:8000`
and the NPMplus admin GUI at `https://localhost:18081`. Neither is exposed
to the internet.

### 5.3 The app is alive but not exposed
```text
❯ curl http://localhost:8000/entries          # through the SSH tunnel
{"entries":[{"id":"seed-1","work":"Deployed the LearningSteps environment",...},
            {"id":"seed-2","work":"Reviewed the handbook",...}],"count":2}
```
The app works and returns the seeded entries, but only through the
identity-verified tunnel. No public entry point exists yet.

### 5.4 NPMplus admin login
Opened `https://localhost:18081` (self-signed certificate warning, which is
expected for the admin GUI over the tunnel). Logged in with the default
credentials from `scripts/setup-npmplus.sh`: login succeeded.
These credentials are public in the course repository (finding **F-11**), so
the password is changed immediately (next step).
Default admin password changed via *User menu → Change Password* (F-11
mitigated for this deployment; the default still exists in the setup script).

### 5.5 Proxy Host (no TLS yet)
NPMplus GUI → *Hosts → Proxy Hosts → Add Proxy Host*:
domain `ls-vladi.westeurope.cloudapp.azure.com`, scheme `http`, forward to
`127.0.0.1:8000`, SSL tab left untouched. The proxy host was created.

### 5.6 Evidence "before TLS": data in plaintext
```text
❯ curl -i http://ls-vladi.westeurope.cloudapp.azure.com/entries
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 18:36:31 GMT
Content-Type: application/json
Content-Length: 480
Connection: keep-alive
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
...
{"entries":[{"id":"seed-1","work":"Deployed the LearningSteps environment",...},...],"count":2}
```
The app is now publicly reachable, **over plain HTTP** (finding F-06). The
full journal content is readable by anyone on the network path (Wi-Fi, ISP,
proxies). It is also reachable **without any authentication** (F-05, Day 3).
NPMplus already adds some security headers (`X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`), but there is no
`Strict-Transport-Security` header, because there is no TLS yet.

### 5.7 Enable TLS (Let's Encrypt)
**Difference from `handbook.md`:** in NPMplus `2026-06-25-r1` the proxy host
tab is called **TLS**, not "SSL", and has extra options (mTLS, HTTP/3, Reuse
Key).

Settings chosen (*Proxy Host → Edit → TLS*):

| Option | Value | Reason |
|---|---|---|
| TLS Certificate | Request a new Certificate | free, browser-trusted Let's Encrypt cert |
| mTLS Certificate | None | no client-certificate auth needed |
| Force HTTPS | on | HTTP is redirected to HTTPS |
| HSTS Enabled (2 years) | on | browsers refuse plain HTTP for this host afterwards (prevents SSL-stripping) |
| HSTS Subdomains+Preload | off | preload is hard to undo, not suitable for a lab hostname |
| HTTP/3 Support | off | needs UDP/443, which the NSG does not allow |
| Reuse Key | off | fresh private key on every renewal |
| Use DNS Challenge | off | the HTTP-01 challenge works because port 80 is open |

Verification over HTTPS:
```text
❯ curl -i https://ls-vladi.westeurope.cloudapp.azure.com/entries
HTTP/2 200
date: Sun, 01 Nov 2026 18:44:14 GMT
content-type: application/json
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
strict-transport-security: max-age=63072000
x-frame-options: SAMEORIGIN
...
{"entries":[...],"count":2}
```
- `curl` succeeded **without `-k`**, so the certificate is trusted by the
  public CA chain (Let's Encrypt).
- `HTTP/2`: the connection is TLS-encrypted.
- `strict-transport-security: max-age=63072000` (2 years): HSTS is active.

HTTP is redirected:
```text
❯ curl -i http://ls-vladi.westeurope.cloudapp.azure.com/entries
HTTP/1.1 301 Moved Permanently
Location: https://ls-vladi.westeurope.cloudapp.azure.com/entries
...
```
Plain HTTP no longer returns data, only a permanent redirect to HTTPS. **F-06
mitigated.**

### 5.8 Evidence "before WAF": attack payloads pass through
```text
❯ curl -i "https://ls-vladi.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users"
HTTP/2 200
...
{"entries":[...],"count":2}
```
The SQL-injection payload reaches the application unfiltered (finding
**F-07**). This app ignores the `id` parameter, but a vulnerable endpoint
would get the payload as is. TLS protects the transport, not the content
of a request.
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" "https://ls-vladi.westeurope.cloudapp.azure.com/entries?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
200
```
The XSS payload also passes (`200`).

### 5.9 Enable the WAF (CrowdSec AppSec + OWASP CRS)
On the VM:
```bash
sudo docker exec crowdsec cscli bouncers add npmplus
```
This registers NPMplus as a CrowdSec *bouncer* (enforcement point) and prints
an API key **once**. The key is a secret and is not recorded here.

Enable the bouncer and store the key **without echoing it** (keeps it off
the screen and out of shell history):
```bash
read -rs KEY && sudo sed -i -e 's/^ENABLED=.*/ENABLED=true/' \
  -e "s/^API_KEY=.*/API_KEY=$KEY/" /opt/npmplus/crowdsec/crowdsec.conf && unset KEY
```
(Deviation from `handbook.md`, which uses `nano` to paste the key. The
result is the same, but the key never appears on screen.)
```text
$ sudo sed -E 's/^(API_KEY=).+/\1***set***/' /opt/npmplus/crowdsec/crowdsec.conf
ENABLED=true
API_URL=http://127.0.0.1:8080
APPSEC_URL=http://127.0.0.1:7422
API_KEY=***set***
```
```bash
cd /opt/npmplus && sudo docker compose restart npmplus
```

### 5.10 Verification "after WAF"
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" "https://ls-vladi.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users"
403
```
The same SQL-injection payload is now **blocked at the proxy** (`403`) and
never reaches the application.
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" "https://ls-vladi.westeurope.cloudapp.azure.com/entries?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
403
```
The XSS payload is blocked too. **F-07 mitigated.**
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" https://ls-vladi.westeurope.cloudapp.azure.com/entries
200
```
A legitimate request from the same IP still works: no false positive, and no
IP-wide ban after the test attacks.

### 5.11 CrowdSec alerts: a real attack caught within minutes
```text
$ sudo docker exec crowdsec cscli alerts list
| ID | value            | reason                                               | country | as                       | decisions | created_at           | kind     |
| 27 | Ip:91.38.119.x   | anomaly score block: xss: 40, anomaly: 40,           | DE      | 3320 Deutsche Telekom AG |           | 2026-11-01T19:07:53Z | waf      |
| 26 | Ip:91.38.119.x   | anomaly score block: sql_injection: 40, anomaly: 40, | DE      | 3320 Deutsche Telekom AG |           | 2026-11-01T19:04:52Z | waf      |
| 25 | Ip:45.45.237.39  | anomaly score block: lfi: 5, anomaly: 10,            | US      | 400529 INFRALY-LLC       |           | 2026-11-01T19:03:55Z | waf      |
|  … | Ip:45.45.237.39  | anomaly score block: lfi: 5, anomaly: 5,             | US      | 400529 INFRALY-LLC       |           | 2026-11-01T19:03:55Z | waf      |
|  5 | Ip:45.45.237.39  | crowdsecurity/appsec-native                          | US      | 400529 INFRALY-LLC       | ban:1     | 2026-11-01T19:03:53Z | crowdsec |
|  1 | Ip:45.45.237.39  | anomaly score block: lfi: 5, anomaly: 5,             | US      | 400529 INFRALY-LLC       |           | 2026-11-01T19:03:53Z | waf      |
```

Analysis:
- **#26, #27: our own test payloads**, classified correctly by the OWASP CRS
  as `sql_injection` and `xss`. Each got an anomaly score of 40, above the
  blocking threshold.
- **#1–#25: a real, unsolicited attack.** An external host `45.45.237.39`
  (US, hosting provider AS400529 INFRALY-LLC) sent ~24 **LFI (Local File
  Inclusion)** probes within ~2 seconds, about **1 minute after the WAF was
  enabled** and only ~20 minutes after the hostname got a public HTTPS
  certificate. The likely trigger: Let's Encrypt certificates are published
  in public **Certificate Transparency logs**, which scanners monitor for new
  hostnames.
- **#5: automatic response.** CrowdSec's `appsec-native` scenario turned the
  repeated WAF hits into an IP-wide **ban** (`ban:1`), so further requests
  from that IP are dropped regardless of their content.
- Our own IP got no ban decision. Two payloads are below the scenario
  threshold, which matches the `200` for the normal request above.

This is the best possible argument for Day 2: on the real internet, a
newly published service is attacked within minutes, not days.

### 5.12 "Read the fine print": what CrowdSec shares
```text
$ sudo docker exec crowdsec cscli console status
| Central API (CAPI) | ✅ authenticated |
| Enrolled           | ❌ not enrolled  |
| custom   | ✅ | Forward alerts from custom scenarios to the console  |
| manual   | ❌ | Forward manual decisions to the console              |
| tainted  | ✅ | Forward alerts from tainted scenarios to the console |
| context  | ❌ | Forward context with alerts to the console           |
```
Interpretation:
- **CAPI authenticated:** the agent talks to CrowdSec's Central API. It
  sends *signals* (attacking IP, scenario name, timestamp) and in return
  receives the **community blocklist**. This is on by default.
- **Not enrolled:** the instance is not linked to a CrowdSec Console account,
  so the `custom`/`tainted` forwarding options currently have no effect.
- **context ❌:** request details (URIs, payloads) are not sent.
- Privacy note: during testing, **our own IP** produced WAF alerts. Shared
  signals can include IPs of legitimate testers or users. That is a data
  protection question (GDPR) for a real deployment.

**Decision:** keep CAPI signal sharing **on**. The community blocklist blocks
known attackers before they send their first payload. Signals carry only the
attacker IP, scenario and time (`context` is off), and the instance is not
enrolled in the console. This is a deliberate, documented trade-off. To
reverse it, set `api.server.online_client.sharing: false` in the CrowdSec
config, or use `cscli console disable --all` for the console options.

**Day 2 result: done and verified.** Public entry point over HTTPS only
(Let's Encrypt, Force HTTPS, HSTS); SQLi/XSS blocked with `403`; legitimate
traffic still `200`; a real external LFI scanner detected and banned
automatically.

---

## Step 6 — Day 3: Identity-based API access ✅

Goal: no request reaches the API without a valid Entra ID identity
(oauth2-proxy behind NPMplus *Auth Request*). Addresses **F-05**.

### 6.1 Register an Entra ID application (on the Mac)
The app registration is named per student (`…-ls-vladi`), because the course
tenant is shared and display names would otherwise collide.
```text
❯ APP_ID=$(az ad app create --display-name learningsteps-oauth2-proxy-ls-vladi \
    --sign-in-audience AzureADMyOrg --query appId -o tsv); echo $APP_ID
45adf4cc-1808-45f6-8550-0ffe92680e12
```
`AzureADMyOrg`: single-tenant, so only accounts from the course tenant can
sign in. The app (client) ID is an identifier, not a secret.
```bash
az ad app update --id $APP_ID --identifier-uris api://$APP_ID     # OK, no output
```
```text
❯ az ad sp create --id $APP_ID --query id -o tsv
ae215f48-db74-440e-af81-74dccd0e528e
```
`az ad app create` creates only the *application object* (the global
definition). The **service principal** is its instance in this tenant.
Without it the app cannot act as a sign-in or token audience
(`az ad sp show --id $APP_ID` returns 404).
```text
❯ SECRET=$(az ad app credential reset --id $APP_ID --query password -o tsv)
WARNING: The output includes credentials that you must protect. ...
```
The client secret is captured into a shell variable and **never printed**
(not recorded here). Default lifetime is 1 year. A shorter `--end-date`,
or a certificate / federated credential instead of a secret, would be
better in production.
```text
❯ TENANT_ID=$(az account show --query tenantId -o tsv); echo $TENANT_ID
c0531484-50fa-4ff2-97df-b1f2d4810603
```
```text
❯ OBJECT_ID=$(az ad app show --id $APP_ID --query id -o tsv); echo $OBJECT_ID
e17e53e2-28dc-4e2f-98e4-b2386bb9dc16
```
```bash
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body '{"api":{"requestedAccessTokenVersion":2}}'          # OK
```
Forces **v2.0 access tokens**. Without it, tokens for `api://$APP_ID` are
v1.0 (`iss: https://sts.windows.net/<tenant>/`), and oauth2-proxy, which is
configured with the v2.0 issuer, rejects them.
```bash
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body "{\"api\":{\"oauth2PermissionScopes\":[{\"id\":\"$(uuidgen)\", ... ,\"value\":\"access_as_user\"}]}}"   # OK
```
Exposes the scope `access_as_user`. Without any exposed scope, requesting a
token for `api://$APP_ID` fails with `AADSTS650057: Invalid resource`.
(`uuidgen` on macOS replaces the handbook's `python3 -c "import uuid…"`.)
Verification of the app registration:
```text
❯ az ad app show --id $APP_ID --query "{tokenVersion:api.requestedAccessTokenVersion, scopes:api.oauth2PermissionScopes[].value, identifierUris:identifierUris}" -o json
{
  "identifierUris": [ "api://45adf4cc-1808-45f6-8550-0ffe92680e12" ],
  "scopes": [ "access_as_user" ],
  "tokenVersion": 2
}
```
```bash
az ad app update --id $APP_ID \
  --web-redirect-uris "https://ls-vladi.westeurope.cloudapp.azure.com/oauth2/callback"   # OK
```
The reply URL must be HTTPS (Entra rejects plain-HTTP reply URLs except
`localhost`), which is why Day 3 depends on Day 2's TLS. Without it the
browser login fails with `AADSTS500113: No reply address is registered`.

### 6.2 Configure oauth2-proxy on the VM
Values are pushed **from the Mac's shell variables** over SSH (heredoc piped
into `sudo bash -s`). The client secret is never typed, printed or stored in
shell history. The env file is also restricted to root (`chmod 600`):
`setup-oauth2-proxy.sh` creates it with the default umask, which makes it
**world-readable** for every local user on the VM (new finding, same class
as F-09).

**Problem:** the first attempt failed:
```text
volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com@20.101.139.95: Permission denied (publickey).
```
**Cause:** the Entra ID SSH certificate from `az ssh config` (Step 5.1) had
expired. It is valid for about 1 hour by design.
**Fix:** re-run `az ssh config …` to get a fresh certificate. This is the
security property working as intended: a leaked certificate expires on its own.
```text
❯ az ssh config --resource-group rg-ls-vladi --name vm-ls-vladi --file azssh_config --overwrite
.../id_rsa already exists.
Overwrite (y/n)? y
Generated SSH certificate .../id_rsa.pub-aadcert.pub is valid until 2026-11-01 09:47:02 PM in local time.

❯ ssh -F azssh_config 20.101.139.95 "sudo bash -s" <<EOF
set -e
sed -i -e "s#^OAUTH2_PROXY_CLIENT_ID=.*#OAUTH2_PROXY_CLIENT_ID=$APP_ID#" \
       -e "s#^OAUTH2_PROXY_CLIENT_SECRET=.*#OAUTH2_PROXY_CLIENT_SECRET=$SECRET#" \
       -e "s#^OAUTH2_PROXY_OIDC_ISSUER_URL=.*#OAUTH2_PROXY_OIDC_ISSUER_URL=https://login.microsoftonline.com/$TENANT_ID/v2.0#" \
       -e "s#^OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES=.*#OAUTH2_PROXY_OIDC_EXTRA_AUDIENCES=api://$APP_ID#" \
       /etc/oauth2-proxy/oauth2-proxy.env
chmod 600 /etc/oauth2-proxy/oauth2-proxy.env
sed -i "s#REPLACE_WITH_DOMAIN#ls-vladi.westeurope.cloudapp.azure.com#" /etc/systemd/system/oauth2-proxy.service
echo configured
EOF
configured
```

### 6.3 Start oauth2-proxy
```text
❯ ssh -F azssh_config 20.101.139.95 "sudo systemctl daemon-reload && sudo systemctl enable --now oauth2-proxy && systemctl is-active oauth2-proxy"
Created symlink /etc/systemd/system/multi-user.target.wants/oauth2-proxy.service → /etc/systemd/system/oauth2-proxy.service.
active
```
oauth2-proxy listens on `127.0.0.1:4180` only and is not exposed. NPMplus
reaches it through `AUTH_REQUEST_OAUTH2PROXY_UPSTREAM`.

### 6.4 Wire identity enforcement into NPMplus (Auth Request)
**Problem:** saving the proxy host with *Auth Request → oauth2proxy* in the
NPMplus GUI returned **HTTP 403** (logout in the admin GUI also failed).
**Cause:** the Day 2 WAF protects the whole NPMplus instance, including its
own admin API. Admin requests through the SSH tunnel arrive from `127.0.0.1`,
and the CRS flags the proxy-host update payload (nginx/auth config in the
JSON body) as an attack. This is the known issue in `handbook.md`, Day 2
troubleshooting: the defense blocks its own operator.
**Fix (as in the handbook):** temporarily disable the bouncer, make the admin
change, then re-enable it.
```bash
# on the VM
sudo sed -i 's/^ENABLED=.*/ENABLED=false/' /opt/npmplus/crowdsec/crowdsec.conf && cd /opt/npmplus && sudo docker compose restart npmplus
```
Then, in the GUI: *Proxy Host → Edit → Auth Request → oauth2proxy → Save*.
Saved successfully.
```bash
# re-enable the WAF immediately afterwards
sudo sed -i 's/^ENABLED=.*/ENABLED=true/' /opt/npmplus/crowdsec/crowdsec.conf && cd /opt/npmplus && sudo docker compose restart npmplus
```
The WAF was off only for the few minutes of the admin change. A better
long-term fix is to exempt the admin interface (port 81, source `127.0.0.1`)
from AppSec inspection, so that admin work never needs the public WAF
switched off.

### 6.5 Verification: the identity gate
Unauthenticated request:
```text
❯ curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" https://ls-vladi.westeurope.cloudapp.azure.com/entries
302 https://ls-vladi.westeurope.cloudapp.azure.com/oauth2/sign_in?rd=https://ls-vladi.westeurope.cloudapp.azure.com/entries
```
Before Day 3 the same request returned `200` with all journal entries. Now
the data is not returned. The client is redirected to the oauth2-proxy
sign-in, and `rd=` remembers the original URL. **F-05 mitigated.**
Malformed bearer token:
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer garbage" https://ls-vladi.westeurope.cloudapp.azure.com/entries
302
```
An invalid token gets no free pass and is treated as unauthenticated.

### 6.6 Browser login: HTTP 500 at `/oauth2/callback`
The Microsoft sign-in itself succeeded: the browser came back to
`/oauth2/callback?code=…`. oauth2-proxy then answered **500 Internal Server
Error**. Root cause from the log:
```text
❯ ssh -F azssh_config 20.101.139.95 "sudo journalctl -u oauth2-proxy --since '30 min ago' --no-pager | grep -iE 'callback|error|500' | tail -10"
[oauthproxy.go:902] Error creating session during OAuth2 callback: neither the id_token nor the profileURL set an email
[validator.go:60] Rejecting invalid redirect "https://ls-vladi.westeurope.cloudapp.azure.com/...": domain / port not in whitelist
"GET /oauth2/callback?code=<redacted>&state=<redacted>&session_state=<redacted>" ... 500
```
1. **No `email` claim.** oauth2-proxy identifies users by e-mail by
   default, but the cloud-only account `…@cybersteps.onmicrosoft.com` has no
   `mail` attribute in Entra ID, so the token has no `email` claim. The
   identity is in `preferred_username` (the UPN).
2. **Redirects to our own domain rejected.** Without `--whitelist-domain`,
   oauth2-proxy refuses absolute post-login redirects (`rd=`), even to its
   own host.

**Fix:**
```bash
ssh -F azssh_config 20.101.139.95 "printf 'OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username\nOAUTH2_PROXY_WHITELIST_DOMAINS=ls-vladi.westeurope.cloudapp.azure.com\n' | sudo tee -a /etc/oauth2-proxy/oauth2-proxy.env >/dev/null && sudo systemctl restart oauth2-proxy && systemctl is-active oauth2-proxy"
```

**New finding (log hygiene):** oauth2-proxy logs the full callback URL,
including the one-time **authorization code**, `state` and `session_state`.
The code is single-use and short-lived, so the risk is low. Still,
credentials-in-logs is an anti-pattern, especially once these logs are
forwarded to Sentinel (Day 5). The values are redacted here.
```text
❯ ... | sudo tee -a /etc/oauth2-proxy/oauth2-proxy.env ... && systemctl is-active oauth2-proxy
active
```

### 6.7 Verification: real browser login
`https://ls-vladi.westeurope.cloudapp.azure.com/entries` in the browser goes
to the Microsoft sign-in (account
`volodymyr.anatolijovickharkov@cybersteps.onmicrosoft.com`) and comes back
with the app data:
```json
{ "entries": [ { "id": "seed-1", "work": "Deployed the LearningSteps environment", ... },
               { "id": "seed-2", "work": "Reviewed the handbook", ... } ],
  "count": 2 }
```
The end-to-end identity flow works: Entra ID (OIDC) → oauth2-proxy session
cookie → NPMplus Auth Request → FastAPI.

### 6.8 Defense-in-depth ordering: WAF behind the identity gate
Same SQL-injection payload as Day 2, **unauthenticated**:
```text
❯ curl -s -o /dev/null -w "%{http_code}\n" "https://ls-vladi.westeurope.cloudapp.azure.com/entries?id=1+UNION+SELECT+*+FROM+users"
302
```
On Day 2 this returned `403`. Now it returns `302` (redirect to sign-in).
The Auth Request check runs **before** the WAF check, so an unauthenticated
attacker is sent to login, and the attempt never shows up as a WAF hit.
Same payload in the **authenticated** browser tab: **`403 Forbidden`**.
The WAF still protects against users with a valid (or stolen) session,
which is arguably the more realistic threat. Layering controls changes what
each one sees, so it does not simply add coverage.

**Day 3 result: done and verified.** No anonymous access; invalid tokens are
rejected; real Entra ID login works end to end; WAF active behind the gate.
