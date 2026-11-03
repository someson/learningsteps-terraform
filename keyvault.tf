# ── F-09 / F-10: database secrets in Key Vault ────────────────────────────────
# Before: the DB admin password was templated into custom_data and into the
# systemd unit (world-readable), and the app connected as the admin.
# Now:
#   - db-admin-password: the existing admin password (var.db_admin_password),
#     used on the VM only by scripts/setup-db-secrets.sh to manage the schema
#     and the app role.
#   - db-app-password: generated here for the least-privilege role
#     var.db_app_username (SELECT/INSERT/UPDATE/DELETE on entries only).
# The VM reads both with its system-assigned managed identity; nothing secret
# is stored on the VM's disk or in custom_data.
#
# Still in Terraform state: both values (and the admin password via the
# PostgreSQL server resource). That is F-15 (remote state with RBAC).

locals {
  # 3-24 chars, letters/digits/hyphens, globally unique -> sanitized prefix + hash.
  key_vault_name = "kv-${substr(replace(lower(var.prefix), "/[^a-z0-9]/", ""), 0, 12)}-${substr(md5(azurerm_resource_group.main.id), 0, 6)}"
}

resource "random_password" "db_app" {
  length  = 32
  special = false # goes into a postgresql:// URL; 32 alphanumerics are ~190 bits
}

resource "azurerm_key_vault" "main" {
  name                       = local.key_vault_name
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  # Lab setting: lets `terraform destroy` + re-deploy reuse the name. In
  # production enable purge protection.
  purge_protection_enabled = false

  # Access policies instead of Azure RBAC on purpose: they take effect
  # immediately. With RBAC, the role assignment for the operator propagates
  # for minutes and the first `terraform apply` fails with 403 on the secrets.
  enable_rbac_authorization = false

  # Firewall: only the VM's subnet (service endpoint) and the operator's IP
  # (Terraform reads the secrets on every plan). Everything else gets 403.
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = [var.admin_source_ip]
    virtual_network_subnet_ids = [azurerm_subnet.app.id]
  }

  # The identity running Terraform manages the secrets.
  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "List", "Set", "Delete", "Purge", "Recover"]
  }

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# The VM may only read secrets (no list, no write).
resource "azurerm_key_vault_access_policy" "vm" {
  key_vault_id       = azurerm_key_vault.main.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_linux_virtual_machine.vm.identity[0].principal_id
  secret_permissions = ["Get"]
}

resource "azurerm_key_vault_secret" "db_admin_password" {
  name         = "db-admin-password"
  value        = var.db_admin_password
  key_vault_id = azurerm_key_vault.main.id
  content_type = "PostgreSQL admin password (${var.db_admin_username})"
}

resource "azurerm_key_vault_secret" "db_app_password" {
  name         = "db-app-password"
  value        = random_password.db_app.result
  key_vault_id = azurerm_key_vault.main.id
  content_type = "PostgreSQL app role password (${var.db_app_username})"
}
