resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Priorities 100-199 are reserved for Sentinel's auto-block playbook
  # (templates/block-ip-playbook.json creates "sentinel-block-<ip>" deny
  # rules at priority 100). Found by testing: with the allow-* rules
  # originally at 100/110/120 and the deny rule at 200, the lower-numbered
  # (higher-precedence) allow-* rules always won and the auto-block was
  # silently a no-op — confirmed live (SSH and the app both remained
  # reachable from a "blocked" IP). Baseline allow rules now start at 1000
  # so the auto-block deny rule always evaluates first.
  #
  # Day 1 (F-01): SSH only from the operator's trusted IP (var.admin_source_ip),
  # never from the whole internet.
  security_rule {
    name                       = "allow-ssh"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.admin_source_ip
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-http"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 1020
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

# Day 4's Private Link migration adds a dedicated delegated subnet for
# PostgreSQL plus a private DNS zone here (azurerm_subnet.db,
# azurerm_private_dns_zone.postgres, azurerm_private_dns_zone_virtual_network_link.postgres)
# — deliberately not part of the baseline. See handbook.md Day 4.
