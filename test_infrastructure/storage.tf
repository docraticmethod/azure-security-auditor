# Storage account fixtures — mix of secure and insecure.

# FLAW: public blob/container access enabled.
resource "azurerm_storage_account" "public_sa" {
  name                     = "publicsa001"
  resource_group_name      = "rg-demo"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}

# FLAW: public network access left open, blob public access enabled.
resource "azurerm_storage_account" "open_sa" {
  name                     = "opensa002"
  resource_group_name      = "rg-demo"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true
}

# OK: hardened storage account.
resource "azurerm_storage_account" "secure_sa" {
  name                     = "securesa003"
  resource_group_name      = "rg-demo"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  min_tls_version                 = "TLS1_2"
}
