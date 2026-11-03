# ── Network visibility: VNet flow logs + Traffic Analytics ───────────────────
# The NSG drops everything that is not 80/443 (or 22 from admin_source_ip),
# plus every IP that Sentinel blocked. Until now none of that was recorded:
# port scans, SSH attempts from other IPs and repeat visits of blocked
# attackers were invisible. VNet flow logs record every flow with the NSG
# decision (allowed / denied, and which rule), and Traffic Analytics writes
# them to the Log Analytics workspace (table NTANetAnalytics) every 10 min.
#
# Why VNet flow logs and an ARM template:
#   - Azure no longer allows creating NEW NSG flow logs (retirement, see
#     https://learn.microsoft.com/azure/network-watcher/nsg-flow-logs-overview).
#     VNet flow logs are the replacement.
#   - azurerm 3.x (pinned in provider.tf) only supports NSG flow logs in
#     azurerm_network_watcher_flow_log (network_security_group_id is required).
#     Moving to azurerm 4.x would be a large, separate migration, so the flow
#     log is deployed as a small ARM template — the same pattern as the
#     Sentinel playbook (templates/block-ip-playbook.json).

locals {
  network_watcher_name = coalesce(var.network_watcher_name, "NetworkWatcher_${azurerm_resource_group.main.location}")
}

# Fails early with a clear error if the regional Network Watcher does not exist
# (it is created automatically by Azure when the first VNet in a region is
# created, unless the subscription opted out).
data "azurerm_network_watcher" "regional" {
  name                = local.network_watcher_name
  resource_group_name = var.network_watcher_resource_group
}

# Raw flow logs land here (required by Azure); Traffic Analytics reads them.
# Name: 3-24 lowercase alphanumerics, globally unique -> deterministic suffix.
resource "azurerm_storage_account" "flowlogs" {
  name                            = "stfl${substr(md5(azurerm_resource_group.main.id), 0, 10)}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# Deployed into the Network Watcher's resource group, because the flow log is
# a child resource of the Network Watcher. Covers the whole VNet (both subnets).
resource "azurerm_resource_group_template_deployment" "vnet_flow_log" {
  name                = "deploy-vnet-flow-log-${var.prefix}"
  resource_group_name = var.network_watcher_resource_group
  deployment_mode     = "Incremental"

  template_content = file("${path.module}/templates/vnet-flow-log.json")

  parameters_content = jsonencode({
    networkWatcherName  = { value = data.azurerm_network_watcher.regional.name }
    flowLogName         = { value = "fl-vnet-${var.prefix}" }
    location            = { value = data.azurerm_network_watcher.regional.location }
    targetResourceId    = { value = azurerm_virtual_network.main.id }
    storageId           = { value = azurerm_storage_account.flowlogs.id }
    retentionDays       = { value = var.flow_log_retention_days }
    workspaceGuid       = { value = azurerm_log_analytics_workspace.main.workspace_id }
    workspaceRegion     = { value = azurerm_log_analytics_workspace.main.location }
    workspaceResourceId = { value = azurerm_log_analytics_workspace.main.id }
  })
}

# ── Saved searches on NTANetAnalytics (Logs -> Queries -> category "Network") ─
# For external sources SrcIp is empty; the IP is in SrcPublicIps, formatted as
# "<ip>|<flows started>|<flows ended>|<out pkts>|<in pkts>|<out bytes>|<in bytes>",
# several entries separated by spaces. FlowStatus: A = allowed, D = denied.
# FlowDirection: I = inbound. AclRule names the NSG rule that decided.

resource "azurerm_log_analytics_saved_search" "inbound_flows_per_day" {
  name                       = "network-inbound-flows-per-day"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Network"
  display_name               = "Network: inbound internet flows per day (allowed / denied)"

  query = <<-KQL
    NTANetAnalytics
    | where TimeGenerated > ago(30d)
    | where SubType == "FlowLog" and FlowDirection == "I"
    | where FlowType in ("ExternalPublic", "MaliciousFlow")
    | summarize
        DeniedFlows    = sum(DeniedInFlows),
        AllowedFlows   = sum(AllowedInFlows),
        MaliciousFlows = sumif(DeniedInFlows + AllowedInFlows, FlowType == "MaliciousFlow"),
        DeniedSsh      = sumif(DeniedInFlows, DestPort == 22),
        BlockedByRule  = sumif(DeniedInFlows, AclRule has "sentinel-block")
      by Day = startofday(TimeGenerated)
    | order by Day desc
  KQL
}

resource "azurerm_log_analytics_saved_search" "denied_sources" {
  name                       = "network-denied-sources"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Network"
  display_name               = "Network: top denied source IPs (last 24 h)"

  query = <<-KQL
    NTANetAnalytics
    | where TimeGenerated > ago(1d)
    | where SubType == "FlowLog" and FlowDirection == "I" and FlowStatus == "D"
    | mv-expand Entry = split(SrcPublicIps, " ") to typeof(string)
    | extend SrcIP = tostring(split(Entry, "|")[0]), Flows = tolong(split(Entry, "|")[1])
    | where isnotempty(SrcIP)
    | summarize
        Flows   = sum(Flows),
        Ports   = make_set(DestPort, 10),
        Rules   = make_set(AclRule, 5),
        Country = take_any(Country)
      by SrcIP
    | top 50 by Flows
  KQL
}

resource "azurerm_log_analytics_saved_search" "denied_ports" {
  name                       = "network-denied-ports"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Network"
  display_name               = "Network: denied inbound flows by port and NSG rule (last 24 h)"

  query = <<-KQL
    NTANetAnalytics
    | where TimeGenerated > ago(1d)
    | where SubType == "FlowLog" and FlowDirection == "I" and FlowStatus == "D"
    | summarize DeniedFlows = sum(DeniedInFlows) by DestPort, L7Protocol, AclRule
    | order by DeniedFlows desc
  KQL
}
