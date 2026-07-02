# SECURE fixtures — network. These should produce NO findings.

resource "azurerm_network_security_group" "good_nsg" {
  name                = "good-nsg"
  location            = "eastus"
  resource_group_name = "rg-demo"
}

# OK: SSH restricted to a corporate CIDR.
resource "azurerm_network_security_rule" "allow_ssh_corp" {
  name                        = "allow-ssh-corp"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "10.0.0.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "good-nsg"
}

# OK: RDP from a bastion subnet only.
resource "azurerm_network_security_rule" "allow_rdp_bastion" {
  name                        = "allow-rdp-bastion"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "10.0.1.0/27"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "good-nsg"
}

# OK: wildcard source, but the rule DENIES, so it is not an exposure.
resource "azurerm_network_security_rule" "deny_all_ssh" {
  name                        = "deny-all-ssh"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "good-nsg"
}

# OK: wildcard source but OUTBOUND, not an inbound exposure.
resource "azurerm_network_security_rule" "outbound_https" {
  name                        = "outbound-https"
  priority                    = 210
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = "rg-demo"
  network_security_group_name = "good-nsg"
}
