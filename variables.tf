variable "prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "learningsteps"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "westeurope"
}

variable "vm_size" {
  description = "VM size. Standard_D2s_v3 often hits SkuNotAvailable (capacity) in westeurope; v6 sizes use the NVMe disk controller automatically (see vm.tf)."
  type        = string
  default     = "Standard_D2s_v6"
}

variable "vm_admin_username" {
  description = "Admin username for the VM"
  type        = string
  default     = "azureuser"
}

variable "vm_admin_ssh_key" {
  description = "SSH public key for VM access"
  type        = string
}

variable "db_admin_username" {
  description = "Administrator username for PostgreSQL"
  type        = string
  default     = "psqladmin"
}

variable "db_admin_password" {
  description = "Administrator password for PostgreSQL"
  type        = string
  sensitive   = true
}

variable "db_name" {
  description = "Name of the application database"
  type        = string
  default     = "learning_journal"
}
