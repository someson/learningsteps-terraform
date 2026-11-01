resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "psql-${var.prefix}"
  location               = azurerm_resource_group.main.location
  resource_group_name    = azurerm_resource_group.main.name
  version                = "16"
  administrator_login    = var.db_admin_username
  administrator_password = var.db_admin_password
  sku_name               = "B_Standard_B1ms"
  storage_mb             = 32768
  zone                   = "1"

  # Day 4 (F-03, F-04): no public endpoint. The server is injected into
  # snet-db and is reachable only from inside the VNet. Changing these
  # attributes REPLACES the server (data loss), so back it up first; see
  # security/04-data-isolation.md.
  public_network_access_enabled = false
  delegated_subnet_id           = azurerm_subnet.db.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# Day 4: the "allow-all" firewall rule (0.0.0.0–255.255.255.255) is removed.
# Firewall rules do not apply to a VNet-integrated server anyway.

resource "azurerm_postgresql_flexible_server_database" "app" {
  name      = var.db_name
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}
