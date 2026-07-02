# Azure SQL fixtures — firewall exposure.

resource "azurerm_sql_server" "demo" {
  name                         = "sql-demo-001"
  resource_group_name          = "rg-demo"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "PLACEHOLDER_ROTATE_ME"
}

# FLAW: firewall rule allowing the entire IPv4 range (0.0.0.0 - 255.255.255.255).
resource "azurerm_sql_firewall_rule" "allow_all" {
  name                = "allow-all"
  resource_group_name = "rg-demo"
  server_name         = "sql-demo-001"
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}

# FLAW: the classic "Allow Azure services" 0.0.0.0/0.0.0.0 rule.
resource "azurerm_sql_firewall_rule" "azure_services" {
  name                = "allow-azure-services"
  resource_group_name = "rg-demo"
  server_name         = "sql-demo-001"
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}

# OK: firewall scoped to a single office IP.
resource "azurerm_sql_firewall_rule" "office_only" {
  name                = "office-only"
  resource_group_name = "rg-demo"
  server_name         = "sql-demo-001"
  start_ip_address    = "203.0.113.10"
  end_ip_address      = "203.0.113.10"
}
