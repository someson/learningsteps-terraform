resource "azurerm_public_ip" "vm" {
  name                = "pip-${var.prefix}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = lower(var.prefix)
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${var.prefix}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                = "vm-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  size                = var.vm_size
  # v6 sizes (Dsv6, Dasv6, ...) attach disks over NVMe only; older sizes use
  # SCSI. Derived from the size so switching sizes needs no second edit.
  disk_controller_type = can(regex("_v6$", var.vm_size)) ? "NVMe" : "SCSI"
  admin_username       = var.vm_admin_username
  network_interface_ids = [
    azurerm_network_interface.vm.id
  ]

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = var.vm_admin_ssh_key
  }

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Built from static values (server name is deterministic:
  # "psql-${var.prefix}.postgres.database.azure.com", matching
  # postgresql.tf's `name = "psql-${var.prefix}"`) rather than referencing
  # azurerm_postgresql_flexible_server.main.fqdn directly. Found by testing
  # (Day 3's practice DB recreate, `terraform apply -replace=...postgresql_flexible_server.main`):
  # referencing the live resource's computed .fqdn attribute here means ANY
  # replacement of the PostgreSQL server — including the exact "destroy and
  # recreate" operation Day 3 has students practice — makes custom_data
  # "known after apply" and forces the VM itself to be destroyed and
  # recreated too, wiping every bit of Day 1/2/4/5's manually-configured
  # state (NPMplus, oauth2-proxy, CrowdSec — none of which are reprovisioned
  # by cloud-init, only by deploy.py's one-time SSH setup scripts). Confirmed
  # live: after a DB-only `-replace`, the VM's SSH host key changed and
  # Docker/NPMplus/oauth2-proxy were gone entirely. Using a statically
  # derivable FQDN removes the dependency edge, so replacing the database
  # server no longer forces a VM replacement.
  custom_data = base64encode(templatefile("${path.module}/scripts/cloud-init.yaml", {
    database_url = "postgresql://${var.db_admin_username}:${var.db_admin_password}@psql-${var.prefix}.postgres.database.azure.com/${var.db_name}?sslmode=require"
  }))

  # Explicit ordering only (cloud-init's runcmd already retries the DB
  # connection until it succeeds) — keeps "DB should exist before the VM
  # tries to use it" predictable without coupling custom_data to a
  # computed attribute. The firewall rule matters here too: at baseline
  # the DB is public (Day 4 migrates it to Private Link), and a public
  # Flexible Server still denies all connections — including from the VM
  # itself — until a firewall rule permits them. Without this, Terraform
  # can create the VM (and cloud-init's DB setup can start) before the
  # firewall rule exists, causing a real, confirmed-live race: cloud-init's
  # own retry loop eventually connects and creates the table, but
  # deploy.py's separate seeding step (running moments later) can still
  # lose that race and find the table gone.
  depends_on = [
    azurerm_postgresql_flexible_server.main,
    azurerm_postgresql_flexible_server_firewall_rule.allow_all,
  ]
}

resource "azurerm_virtual_machine_extension" "aad_ssh" {
  name                       = "AADSSHLoginForLinux"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADSSHLoginForLinux"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}
