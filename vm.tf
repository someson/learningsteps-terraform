resource "azurerm_public_ip" "vm" {
  name                = "pip-${var.prefix}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = lower(var.prefix)

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
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

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
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
  #
  # F-09: custom_data contains NO secret any more. It only carries the Key
  # Vault name and the DB coordinates; the VM fetches both passwords from Key
  # Vault with its managed identity (scripts/setup-db-secrets.sh, embedded
  # here so cloud-init and the manual migration run the same code).
  custom_data = base64encode(templatefile("${path.module}/scripts/cloud-init.yaml", {
    key_vault_name    = azurerm_key_vault.main.name
    db_host           = "psql-${var.prefix}.postgres.database.azure.com"
    db_name           = var.db_name
    db_admin_username = var.db_admin_username
    db_app_username   = var.db_app_username
    setup_script_b64  = base64encode(file("${path.module}/scripts/setup-db-secrets.sh"))
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
    # The secrets must exist before first boot; the VM's own read access
    # (azurerm_key_vault_access_policy.vm) can only be created after the VM,
    # so cloud-init retries until it works (kv-secret --wait).
    azurerm_key_vault_secret.db_admin_password,
    azurerm_key_vault_secret.db_app_password,
  ]

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [
      tags["created-on"],
      # custom_data only runs on first boot, and changing it REPLACES the VM
      # (wiping NPMplus, oauth2-proxy, CrowdSec — see the comment above).
      # Existing VMs are migrated with scripts/setup-db-secrets.sh instead
      # (security/07-secrets.md); new VMs get the current template.
      custom_data,
      # Azure enables this server-side; azurerm 3.x defaults it to false
      # and would try to switch it off on every apply.
      vm_agent_platform_updates_enabled,
    ]
  }
}

resource "azurerm_virtual_machine_extension" "aad_ssh" {
  name                       = "AADSSHLoginForLinux"
  virtual_machine_id         = azurerm_linux_virtual_machine.vm.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADSSHLoginForLinux"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}

# Day 1 (F-02): allow the identity running Terraform to log in to the VM's OS
# with Entra ID (az ssh vm). Being Owner/Contributor on the subscription does
# NOT grant OS login — Azure separates control-plane rights from VM login.
# Scoped to this single VM (least privilege), not the subscription.
resource "azurerm_role_assignment" "vm_admin_login" {
  scope                = azurerm_linux_virtual_machine.vm.id
  role_definition_name = "Virtual Machine Administrator Login"
  principal_id         = data.azurerm_client_config.current.object_id
}
