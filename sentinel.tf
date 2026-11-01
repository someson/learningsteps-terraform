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
