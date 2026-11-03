# 05 — Day 5: Detection and Response

**Findings addressed:** F-14 (no detection or response).
Full command history: [walkthrough-log.md](walkthrough-log.md), Step 8.

## Problem and threat

Days 1–4 made the system harder to attack, but nobody would *notice* an
attack. Without detection, a scanner can probe for as long as it likes, and
every new hole found later is exploited silently. Without automated response,
even a detected attack waits for a human.

## The pipeline (deployed by `sentinel.tf` + `scripts/setup-json-logging.sh`)

```mermaid
graph LR
    N["NPMplus access.log"] --> F["npmplus-log-forwarder<br/>(JSON → syslog local0, tag nginx)"]
    F --> AMA["Azure Monitor Agent<br/>+ Data Collection Rule"]
    AMA --> LAW[("Log Analytics<br/>Syslog table")]
    LAW --> R["Sentinel scheduled rule<br/>≥5 × 403 per IP / 5 min<br/>(excludes 127.0.0.1)"]
    R --> I["Incident (High)"]
    I --> AR["Automation rule<br/>severity = High"]
    AR --> P["Logic App playbook<br/>(managed identity)"]
    P --> NSG["NSG Deny rule<br/>sentinel-block-&lt;ip&gt;, priority 100"]
```

Least privilege in the chain: the VM's identity can only publish to the DCR;
the playbook's identity is *Network Contributor* on **this NSG only** plus
*Sentinel Responder* on the workspace; Sentinel's service principal may only
trigger this one playbook.

## Evidence: a real attack, handled with no human involved

| Time (UTC) | Event | Evidence |
|---|---|---|
| 19:03:53–55 | External scanner `45.45.237.39` sends 24 LFI probes; WAF answers 403 | `cscli alerts list`; KQL: 24 blocks in 2 s |
| 19:14:07 | Sentinel incident #1 "WAF Attack — High Volume 403s from Single IP", **High** | `SecurityInsights/incidents` |
| 19:14:13–15 | Playbook run **Succeeded** (2.2 s), 6 s after the incident | Logic App `runs` |
| since then | `sentinel-block-45-45-237-39`: **Deny, priority 100, all ports** | `az network nsg rule list` |

**Time to respond: ~10 minutes** from attack to block (log ingestion plus the
5-minute schedule). The response itself took seconds.

KQL behind the rule, over the whole day:

| Source | 403s | Outcome |
|---|---|---|
| `45.45.237.39` | 24 | incident + block |
| `127.0.0.1` | 11 | ignored on purpose (our WAF blocking NPMplus admin calls via the tunnel) |
| operator IP | 3 | no incident: deliberate tests, below the threshold of 5 |

## Live controlled test (second IP: Azure Cloud Shell `134.149.156.75`)

| Request (unauthenticated) | Responses |
|---|---|
| `/entries?id=1+UNION+SELECT…` | `302` ×6 |
| `/oauth2/sign_in?rd=1+UNION+SELECT…` | `403` ×6 |

| Step | Result |
|---|---|
| Sentinel incident #2 | created 21:09:28 UTC, High |
| Playbook run | **Failed**: `SecurityRuleConflict`, "Rules cannot have the same Priority and Direction" |
| After the fix (PR #11) + `terraform apply` + resubmit | **Succeeded**: `sentinel-block-134-149-156-75`, Deny, priority **101** |
| `curl` from the blocked Cloud Shell IP | `000`: no TCP connection, dropped by the NSG |
| `curl` from the operator's Mac | `302`: legitimate user unaffected |

## CrowdSec alerts in Sentinel (attack type per IP)

The access log only says "IP X got a 403". *Why* it was blocked (CRS
category and anomaly score, e.g. `anomaly score block: sql_injection: 40,
anomaly: 40,`) exists only in CrowdSec. `scripts/setup-crowdsec-logging.sh`
installs `crowdsec-alert-forwarder` on the VM: every 30 s it reads new alerts
with `cscli alerts list -o json` and sends each one as JSON to syslog `local0`
(tag `crowdsec`). The existing DCR already collects `local0`, so nothing in
the ingestion pipeline changes.

`sentinel.tf` adds the workspace function **`CrowdSecAlerts`** and two saved
searches (Logs → Queries → category *CrowdSec*):

| Saved search | Shows |
|---|---|
| CrowdSec: attacker IPs by attack type (last 24 h) | `AttackType`, `SourceIP`, country, AS, score, sample URIs |
| CrowdSec: attacks per day by type | alerts and distinct attacker IPs per day and type |

```kql
CrowdSecAlerts
| where TimeGenerated > ago(1d) and AttackType == "sql_injection"
| summarize Alerts = count() by SourceIP, Country
| order by Alerts desc
```

This does **not** close the `302` blind spot below: the identity gate answers
unauthenticated requests before AppSec inspects them, so they produce no
AppSec alert either. Only CrowdSec's log-based scenarios (which read
`access.log` regardless of the status code) can see them. `TimeGenerated` in
`CrowdSecAlerts` is the alert's own creation time; on its first start the
forwarder back-fills the last 24 h.

## Second detection rule: CrowdSec attacker

`sentinel.tf` → `azurerm_sentinel_alert_rule_scheduled.crowdsec_attacker`
("CrowdSec — Attacker Detected by WAF or Log Scenario", **High**). It reads
`CrowdSecAlerts` instead of HTTP status codes:

| Fires when, per external IP in 15 min | Why this threshold |
|---|---|
| 3+ AppSec anomaly blocks (`anomaly score block: …`) | one CRS hit can be a false positive of a real user |
| any other CrowdSec alert (`crowdsecurity/http-*` scenarios, `appsec-native`) | log scenarios are leaky buckets (already many requests); native rules are virtual patches for known CVEs |

The log-based scenarios read `access.log` whatever the status code was, so
this rule also catches unauthenticated attacks that got `302` from the
identity gate, the blind spot of the 403 rule. Excluded: `admin_source_ip`,
private and loopback ranges (no self-block). The rule runs every 5 min over
15 min (tolerates ingestion delay); alerts for the same IP within 1 h are
grouped into one incident, so the playbook runs once per IP. Severity High →
the existing automation rule → the same block-IP playbook → NSG Deny.

## Findings from Day 5

1. **The auto-block could only ever block one attacker.** The playbook
   hard-coded `"priority": 100`. The second block rule conflicted with the
   first (`SecurityRuleConflict`), so detection worked while the response
   silently failed. The real scanner happened to be first, which hid the bug
   until the controlled test. Fixed (PR #11): the playbook reads the NSG and
   uses the next free priority (100, 101, …), and the loop runs with
   concurrency 1.
2. **Detection blind spot caused by Day 3.** Unauthenticated attacks against
   the protected API get `302` from the identity gate *before* the WAF sees
   them. They produce no 403, so the 403-based rule never fires. Mitigation
   options: alert on bursts of 302 → `/oauth2/sign_in` per IP; evaluate AppSec
   before `auth_request`; or ship CrowdSec's own AppSec alerts (which see the
   payload) to Sentinel.
3. **IaC vs. automated response** (found on Day 4): inline NSG rules made
   Terraform delete the playbook's block rules on every `apply`. Fixed with
   standalone `azurerm_network_security_rule` resources.
4. **Threshold tuning matters.** Below 5 hits, testers and users are safe
   from self-blocking. The `127.0.0.1` exclusion prevents a meaningless
   "block localhost" response.
5. **Credentials in logs.** oauth2-proxy logs authorization codes in callback
   URLs, and these logs are now shipped to a central workspace.

6. **Azure-managed drift on the DB subnet.** Azure adds the `Microsoft.Storage`
   service endpoint to the delegated subnet, and Terraform would have removed
   it, which could break backups. Declared in code (PR #12).

### Finding: CrowdSec log acquisition read nothing

`cscli metrics show acquisition` on the live VM returned an **empty table**.
The acquisition config pointed at `/opt/npmplus/nginx/*.log`, but the
crowdsec container only mounts `/opt/npmplus/nginx/logs`, so no file matched.
Since Day 2 only the in-band AppSec (CRS) was working; the log-based
scenarios (probing, path traversal, brute force on paths) never saw a line.
Fix: `/opt/npmplus/nginx/logs/*.log` in `scripts/setup-npmplus.sh`.

## Residual risk

- Blocks are **permanent** (no expiry) and keyed on IP. Attackers rotate IPs,
  and shared IPs (NAT, VPN) can block innocent users. Production: a TTL on
  block rules, an allow-list, and a human review step for low-confidence
  incidents.
- NSG rules have hard limits (1,000 rules per NSG). A busy scanner wave could
  exhaust them. Production: Azure Firewall / Front Door WAF IP sets.
- Detection on HTTP 403 volume and on CrowdSec alerts. Still no detection
  for SSH (`auth`/`authpriv` are collected but have no rule), slow attacks
  under the thresholds, or data access anomalies.
- More automated triggers mean more chances to block a legitimate IP
  permanently (e.g. a shared NAT address that also sends CRS false positives).
  The thresholds above and the admin exclusion limit this; a TTL on block
  rules is still missing.
- ~10 minutes to respond is fine for scanners, too slow for a targeted
  exploit. NRT (near-real-time) rules would cut this.
- Incidents #1 and #2 are still **New**. An analyst should triage it, close it and
  document the outcome.
