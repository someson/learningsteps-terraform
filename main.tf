resource "azurerm_resource_group" "main" {
  name     = "rg-${var.prefix}"
  location = var.location

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}
