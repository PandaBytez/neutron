# Split Tunneling (IP & Domain Routing)

Neutron VPN provides **Global Split Tunneling**, allowing users to specify exact subnets, IPs, and domain names that should route through or bypass the VPN tunnel.

---

## Routing Modes

### 1. `Include` Mode (Route Only Listed Destinations via VPN)
* **Behavior**: Default internet browsing bypasses the VPN over your physical interface, while only specified subnets and domain IPs are routed securely through the WireGuard tunnel.
* **NetworkManager Mechanism**:
  ```bash
  nmcli connection modify <uuid> \
      ipv4.never-default yes \
      ipv6.never-default yes \
      ipv4.routes "10.0.0.0/8, 192.168.10.0/24" \
      ipv6.routes "2001:db8::/32"
  ```
* **Use Case**: Work VPN access where corporate subnets must route through the company tunnel while streaming, gaming, and personal browsing remain on high-speed unthrottled physical internet.

### 2. `Exclude` Mode (Bypass VPN for Listed Destinations)
* **Behavior**: All general traffic routes through the encrypted VPN tunnel, while specified subnets or domains bypass the VPN directly to your local physical gateway.
* **NetworkManager Mechanism**:
  `never-default = no` with specific bypass routes prioritized over the default route.
* **Use Case**: Privacy browsing with exclusions for local services, banking portals, or gaming servers that block VPN exit nodes.

### 3. `Disabled` Mode (Standard Full-Tunnel)
* Restores `never-default = no` and clears all custom static routes.

---

## Route Normalization & Dynamic DNS

### 1. CIDR Normalization
Input routes are parsed and normalized into standard CIDR format:
* Single IPv4 `192.168.1.50` $\rightarrow$ `192.168.1.50/32`
* Single IPv6 `::1` $\rightarrow$ `::1/128`
* Subnets `10.0.0.0/8` $\rightarrow$ `10.0.0.0/8`
* Routes are partitioned into `ipv4.routes` and `ipv6.routes` automatically.

### 2. Client-Side Domain Resolution
For domain entries (e.g., `internal.corp`, `service.local`):
1. The domain is resolved via `std::net::ToSocketAddrs` to all associated IPv4 (`/32`) and IPv6 (`/128`) literals.
2. Resolved IPs are merged with configured CIDRs before applying route arguments to NetworkManager.
3. Resolution is performed in the background during connection or rule modification.

---

## CLI & GUI Configuration

### CLI Commands
```bash
# Check status
neutron-vpn split-tunnel status

# Set routing mode
neutron-vpn split-tunnel set-mode include
neutron-vpn split-tunnel set-mode exclude
neutron-vpn split-tunnel set-mode disabled

# Manage CIDRs & Domains
neutron-vpn split-tunnel add-cidr 10.0.0.0/8
neutron-vpn split-tunnel remove-cidr 10.0.0.0/8
neutron-vpn split-tunnel add-domain internal.corp
neutron-vpn split-tunnel remove-domain internal.corp

# Clear all rules
neutron-vpn split-tunnel clear
```

### GUI Dialog
Available in the **Settings** section of the GUI main window:
* Clean mode selector dropdown (`Disabled`, `Include`, `Exclude`).
* Interactive list editors for CIDRs and Domain names with inline syntax validation.
* Real-time subtitle updates reflecting active rules.
