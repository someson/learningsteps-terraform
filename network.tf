resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]

  # F-09: the VM reaches Key Vault through this service endpoint; the vault's
  # firewall (keyvault.tf) admits this subnet and the operator's IP only.
  service_endpoints = ["Microsoft.KeyVault"]
}

# The NSG itself carries NO inline rules. Each rule is a separate
# azurerm_network_security_rule resource below.
#
# Why (found live on Day 4): with inline `security_rule` blocks Terraform owns
# the NSG's *entire* rule set, so every `terraform apply` silently deleted the
# "sentinel-block-<ip>" deny rules that the Sentinel auto-block playbook adds
# at runtime (templates/block-ip-playbook.json), i.e. Terraform would have
# un-blocked a real attacker. With standalone rule resources Terraform manages
# only its own rules and leaves the playbook's rules alone, while drift on
# OUR rules (e.g. SSH reopened to "*") is still detected.
resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# Priorities 100-199 are reserved for Sentinel's auto-block playbook
# (templates/block-ip-playbook.json creates "sentinel-block-<ip>" deny
# rules at priority 100). Found by testing: with the allow-* rules
# originally at 100/110/120 and the deny rule at 200, the lower-numbered
# (higher-precedence) allow-* rules always won and the auto-block was
# silently a no-op — confirmed live (SSH and the app both remained
# reachable from a "blocked" IP). Baseline allow rules now start at 1000
# so the auto-block deny rule always evaluates first.

# Day 1 (F-01): SSH only from the operator's trusted IP (var.admin_source_ip),
# never from the whole internet.
resource "azurerm_network_security_rule" "allow_ssh" {
  name                        = "allow-ssh"
  priority                    = 1000
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.admin_source_ip
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
}

resource "azurerm_network_security_rule" "allow_http" {
  name                        = "allow-http"
  priority                    = 1010
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
}

resource "azurerm_network_security_rule" "allow_https" {
  name                        = "allow-https"
  priority                    = 1020
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

# ── Day 4 (F-03, F-04): data isolation ─────────────────────────────────────
# PostgreSQL moves off the public internet into its own subnet, delegated to
# Flexible Server (VNet integration). It gets a private IP only, so it is
# reachable from inside the VNet (the VM) and nowhere else.
resource "azurerm_subnet" "db" {
  name                 = "snet-db"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  # Azure adds this service endpoint by itself when a Flexible Server is
  # injected into the subnet (the server reaches Azure Storage for WAL and
  # backups through it). Declared here so Terraform does not try to remove
  # it on every apply (found in a later plan).
  service_endpoints = ["Microsoft.Storage"]

  delegation {
    name = "postgresql"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Private DNS: inside the VNet, psql-<prefix>.postgres.database.azure.com
# resolves to the server's private IP. Outside the VNet the name does not
# resolve at all. The FQDN the app uses (vm.tf) does not change.
resource "azurerm_private_dns_zone" "postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name

  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "postgres-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.main.id

  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}
