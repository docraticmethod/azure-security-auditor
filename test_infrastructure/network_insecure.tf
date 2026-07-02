# INSECURE fixtures — network exposure.
# Expect findings: SSH (22) and RDP (3389) open to the internet from a wildcard source.

resource "azurerm_network_security_group" "bad_nsg" {
  name                = "bad-nsg"
  location            = "eastus"
  resource_group_name = "rg-demo"
}

# FLAW: SSH open to the world from any source.
resource "azurerm_network_security_rule" "allow_ssh_any" {
  name                        = "allow-ssh-any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "bad-nsg"
}

# FLAW: RDP open to the world via the 0.0.0.0/0 CIDR.
resource "azurerm_network_security_rule" "allow_rdp_internet" {
  name                        = "allow-rdp-internet"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "bad-nsg"
}

# FLAW: a port range that spans SSH (covers 22) from Internet service tag.
resource "azurerm_network_security_rule" "allow_range_ssh" {
  name                        = "allow-range"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "20-30"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "bad-nsg"
}
