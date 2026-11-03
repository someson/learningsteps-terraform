data "azurerm_client_config" "current" {}

# Azure Security Insights is the service principal Sentinel uses to trigger Logic App playbooks
data "azuread_service_principal" "sentinel" {
  client_id = "98785600-1bb7-4fb9-b9fa-19afe2c8a360"
}

# ── Log Analytics Workspace ───────────────────────────────────────────────────
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# ── Microsoft Sentinel ────────────────────────────────────────────────────────
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}

# ── Azure Monitor Agent on the VM ─────────────────────────────────────────────
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.29"
  auto_upgrade_minor_version = true

  depends_on = [azurerm_virtual_machine_extension.aad_ssh]

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# ── Data Collection Rule: syslog → Log Analytics ──────────────────────────────
# Collects nginx JSON access log (facility=local0) and auth events
resource "azurerm_monitor_data_collection_rule" "syslog" {
  name                = "dcr-${var.prefix}-syslog"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
      name                  = "law-destination"
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["law-destination"]
  }

  data_sources {
    syslog {
      name           = "syslog-datasource"
      facility_names = ["local0", "auth", "authpriv", "syslog"]
      log_levels     = ["Debug", "Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
      streams        = ["Microsoft-Syslog"]
    }
  }

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "vm_syslog" {
  name                    = "dcra-${var.prefix}-syslog"
  target_resource_id      = azurerm_linux_virtual_machine.vm.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.syslog.id
}

# ── Sentinel Analytics Rule: WAF Attack Detection (Scheduled) ────────────────
# Evaluates every 5 minutes over the last 5-minute window.
# Fires when a single IP triggers ≥5 WAF blocks (403s).
resource "azurerm_sentinel_alert_rule_scheduled" "waf_attack" {
  name                       = "waf-attack-scheduled"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "WAF Attack — High Volume 403s from Single IP"
  description                = "Detects when a single IP generates 5+ WAF blocks (HTTP 403) within a 5-minute window. Indicates active SQLi/XSS probing or brute-force attempt."
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  # NOTE on this query's shape (found + fixed during the NPMplus migration):
  # the old hand-rolled nginx setup wrote raw syslog lines shaped like
  # "nginx: {json}", so ProcessName wasn't reliably parsed by AMA and the
  # query pulled the JSON out of SyslogMessage with a regex. The NPMplus
  # log-forwarder (scripts/setup-json-logging.sh) uses `logger -t nginx`,
  # which AMA/rsyslog parses into a clean ProcessName="nginx" column, with
  # SyslogMessage containing ONLY the JSON body (no "nginx: " prefix) —
  # confirmed via direct Log Analytics queries against a live test
  # deployment. The old regex-based extract() never matched this shape and
  # silently returned zero rows. This version reads ProcessName directly and
  # parses SyslogMessage as JSON with no regex.
  #
  # ClientIP == "127.0.0.1" is excluded — found live during full-course
  # testing: the NPMplus admin API tunnel (Day 2) is itself proxied through
  # nginx and shows up as remote_addr=127.0.0.1. CrowdSec's WAF can flag a
  # normal admin session's own requests as anomalous, and enough of those
  # (e.g. repeated proxy-host PUTs) cross the 5-block threshold on their own —
  # triggering this rule and the Day 5 auto-block playbook against
  # 127.0.0.1, which is a meaningless NSG deny rule (it can never appear as a
  # real inbound source) and confusingly pre-empts the real attack-simulation
  # demo with an unrelated incident.
  query = <<-KQL
    Syslog
    | where ProcessName == "nginx"
    | extend log = parse_json(SyslogMessage)
    | extend StatusCode = toint(log.status)
    | extend ClientIP   = tostring(log.remote_addr)
    | extend Uri        = tostring(log.uri)
    | extend Method     = tostring(log.method)
    | where StatusCode == 403
    | where ClientIP != "127.0.0.1"
    | summarize
        WafBlocks   = count(),
        FirstSeen   = min(TimeGenerated),
        LastSeen    = max(TimeGenerated),
        Uris        = make_set(Uri, 10)
      by ClientIP
    | where WafBlocks >= 5
    | project TimeGenerated = LastSeen, ClientIP, WafBlocks, FirstSeen, Uris
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "ClientIP"
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# ── Logic App Playbook: Block Attacker IP in NSG ──────────────────────────────
# Deployed via ARM template — uses managed identity Sentinel connection
# (avoids OAuth interactive authorization needed by classic API connections)
resource "azurerm_resource_group_template_deployment" "block_ip_playbook" {
  name                = "deploy-block-ip-playbook"
  resource_group_name = azurerm_resource_group.main.name
  deployment_mode     = "Incremental"

  template_content = file("${path.module}/templates/block-ip-playbook.json")

  parameters_content = jsonencode({
    playbookName = { value = "playbook-block-ip-${var.prefix}" }
    nsgName      = { value = azurerm_network_security_group.app.name }
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

locals {
  playbook_outputs      = jsondecode(azurerm_resource_group_template_deployment.block_ip_playbook.output_content)
  playbook_resource_id  = local.playbook_outputs.playbookResourceId.value
  playbook_principal_id = local.playbook_outputs.playbookPrincipalId.value
}

# VM managed identity → Monitoring Metrics Publisher on the DCR
# Required for AMA to authenticate and upload syslog data to Log Analytics
resource "azurerm_role_assignment" "vm_ama_publisher" {
  scope                = azurerm_monitor_data_collection_rule.syslog.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

# Playbook managed identity → Network Contributor on the NSG (to add deny rules)
resource "azurerm_role_assignment" "playbook_network_contributor" {
  scope                = azurerm_network_security_group.app.id
  role_definition_name = "Network Contributor"
  principal_id         = local.playbook_principal_id
}

# Sentinel service principal → Microsoft Sentinel Automation Contributor on the Logic App
# Required so the Sentinel Automation Rule can trigger the playbook
resource "azurerm_role_assignment" "sentinel_can_trigger_playbook" {
  scope                = local.playbook_resource_id
  role_definition_name = "Microsoft Sentinel Automation Contributor"
  principal_id         = data.azuread_service_principal.sentinel.object_id
}

# Playbook managed identity → Microsoft Sentinel Responder on the workspace
resource "azurerm_role_assignment" "playbook_sentinel_responder" {
  scope                = azurerm_log_analytics_workspace.main.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = local.playbook_principal_id
}

# ── Sentinel Automation Rule: trigger playbook on High severity incident ───────
resource "azurerm_sentinel_automation_rule" "block_attacker" {
  name                       = "a1b2c3d4-0000-0000-0000-000000000001"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "Auto-block WAF attacker IP"
  order                      = 1
  enabled                    = true

  condition_json = jsonencode([
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentSeverity"
        operator       = "Equals"
        propertyValues = ["High"]
      }
    }
  ])

  action_playbook {
    logic_app_id = local.playbook_resource_id
    tenant_id    = data.azurerm_client_config.current.tenant_id
    order        = 1
  }

  depends_on = [
    azurerm_resource_group_template_deployment.block_ip_playbook,
    azurerm_role_assignment.playbook_sentinel_responder,
    azurerm_role_assignment.sentinel_can_trigger_playbook,
  ]
}

# ── CrowdSec alerts in Sentinel ───────────────────────────────────────────────
# scripts/setup-crowdsec-logging.sh forwards every CrowdSec alert as JSON to
# syslog local0 (tag "crowdsec"), which the DCR above already collects. Unlike
# the NPMplus access log (only "IP got a 403"), these rows carry the reason:
# the CRS category (lfi, sql_injection, xss, appsec-native, ...) and the
# anomaly score — and they also cover attacks that got a 302 from the identity
# gate and therefore never show up as 403s.
#
# CrowdSecAlerts is a workspace function, usable in any query or rule:
#   CrowdSecAlerts | where AttackType == "sql_injection" | summarize count() by SourceIP
# TimeGenerated is the alert's own creation time (not the forwarding time),
# and rows are de-duplicated by CrowdSec alert id.
resource "azurerm_log_analytics_saved_search" "crowdsec_alerts_function" {
  name                       = "CrowdSecAlerts"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "CrowdSec"
  display_name               = "CrowdSecAlerts (parser)"
  function_alias             = "CrowdSecAlerts"

  query = <<-KQL
    Syslog
    | where ProcessName == "crowdsec"
    | extend a = parse_json(SyslogMessage)
    | project
        TimeGenerated = coalesce(todatetime(a.created_at), TimeGenerated),
        AlertId       = tolong(a.alert_id),
        SourceIP      = tostring(a.source_ip),
        AttackType    = tostring(a.attack_types[0]),
        AttackTypes   = a.attack_types,
        AnomalyScore  = toint(a.anomaly_score),
        Scenario      = tostring(a.scenario),
        Country       = tostring(a.country),
        AsName        = tostring(a.as_name),
        EventsCount   = toint(a.events_count),
        Decision      = tostring(a.decision),
        TargetUris    = a.target_uris,
        UserAgents    = a.user_agents,
        Computer
    | summarize arg_max(TimeGenerated, *) by AlertId
  KQL
}

resource "azurerm_log_analytics_saved_search" "crowdsec_attackers_by_type" {
  name                       = "crowdsec-attackers-by-type"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "CrowdSec"
  display_name               = "CrowdSec: attacker IPs by attack type (last 24 h)"

  query = <<-KQL
    CrowdSecAlerts
    | where TimeGenerated > ago(1d)
    | summarize
        Alerts     = count(),
        MaxScore   = max(AnomalyScore),
        Scenarios  = make_set(Scenario, 10),
        SampleUris = make_set(TargetUris, 5),
        FirstSeen  = min(TimeGenerated),
        LastSeen   = max(TimeGenerated)
      by AttackType, SourceIP, Country, AsName
    | order by AttackType asc, Alerts desc
  KQL

  depends_on = [azurerm_log_analytics_saved_search.crowdsec_alerts_function]
}

resource "azurerm_log_analytics_saved_search" "crowdsec_attacks_per_day" {
  name                       = "crowdsec-attacks-per-day"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "CrowdSec"
  display_name               = "CrowdSec: attacks per day by type"

  query = <<-KQL
    CrowdSecAlerts
    | where TimeGenerated > ago(30d)
    | summarize Alerts = count(), AttackerIPs = dcount(SourceIP)
      by Day = startofday(TimeGenerated), AttackType
    | order by Day desc, Alerts desc
  KQL

  depends_on = [azurerm_log_analytics_saved_search.crowdsec_alerts_function]
}

# ── Sentinel Analytics Rule: CrowdSec attacker (Scheduled) ────────────────────
# Second detection path next to the 403-based rule above. It reads the alerts
# that CrowdSec itself raised (CrowdSecAlerts), so it fires on:
#   - AppSec / CRS blocks ("anomaly score block: ...", appsec-native), and
#   - CrowdSec's log-based scenarios (http-probing, http-sqli-probbing,
#     http-path-traversal-probing, ...). These read access.log regardless of
#     the status code, so they also see unauthenticated attacks that the
#     identity gate answers with 302 — the blind spot of the 403 rule.
#
# Threshold: 3+ AppSec anomaly blocks per IP, or any other CrowdSec alert.
# Log-based scenarios are leaky buckets, so one alert already means "many
# suspicious requests"; appsec-native are virtual patches for known CVEs.
# A single CRS anomaly hit can be a false positive of a real user, hence 3.
#
# Severity High -> the existing automation rule runs the block-IP playbook.
# The operator's admin_source_ip and private / loopback ranges are excluded
# so the operator can never block themselves.
#
# Window: query_period 15 min, run every 5 min. The 10 min overlap tolerates
# Syslog ingestion delay; duplicate alerts for one IP are merged into one
# incident by the grouping block (1 h), so the playbook runs once per IP.
locals {
  admin_source_cidr = strcontains(var.admin_source_ip, "/") ? var.admin_source_ip : "${var.admin_source_ip}/32"
}

resource "azurerm_sentinel_alert_rule_scheduled" "crowdsec_attacker" {
  name                       = "crowdsec-attacker-scheduled"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  display_name               = "CrowdSec — Attacker Detected by WAF or Log Scenario"
  description                = "An external IP triggered 3+ CrowdSec AppSec anomaly blocks, or any CrowdSec log-based scenario / virtual patch, within 15 minutes. Covers unauthenticated attacks that never produce a 403."
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    CrowdSecAlerts
    | where isnotempty(SourceIP)
    | where not(ipv4_is_private(SourceIP)) and not(ipv4_is_in_range(SourceIP, "127.0.0.0/8"))
    | where not(ipv4_is_in_range(SourceIP, "${local.admin_source_cidr}"))
    | summarize
        Alerts        = count(),
        AnomalyBlocks = countif(Scenario startswith "anomaly score block"),
        OtherAlerts   = countif(not(Scenario startswith "anomaly score block")),
        AttackTypes   = make_set(AttackType, 10),
        Scenarios     = make_set(Scenario, 10),
        MaxScore      = max(AnomalyScore),
        FirstSeen     = min(TimeGenerated),
        LastSeen      = max(TimeGenerated)
      by SourceIP
    | where AnomalyBlocks >= 3 or OtherAlerts > 0
    | project TimeGenerated = LastSeen, SourceIP, Alerts, AttackTypes, Scenarios, MaxScore, FirstSeen
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }

  custom_details = {
    Alerts      = "Alerts"
    AttackTypes = "AttackTypes"
    Scenarios   = "Scenarios"
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      entity_matching_method  = "Selected"
      by_entities             = ["IP"]
      reopen_closed_incidents = false
    }
  }

  depends_on = [
    azurerm_sentinel_log_analytics_workspace_onboarding.main,
    azurerm_log_analytics_saved_search.crowdsec_alerts_function,
  ]
}
