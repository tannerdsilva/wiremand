# Wiremand

**A secure, low-overhead WireGuard server management daemon & CLI for Linux**

## Overview

Wiremand is a Swift-based command-line tool and systemd daemon designed to automate the lifecycle management of WireGuard VPN configurations. It handles client provisioning, automatic revocation, domain segmentation, firewall whitelisting, DNS integration, and geolocation tracking via a single cohesive interface.

## Features

🔑 Client Lifecycle Management - Create, list, rename, assign IPv4, extend expiry, and revoke clients

🌐 Domain Segmentation - Partition clients into isolated logical domains with dedicated security keys

🛡️ Per-Client Firewall Whitelisting - Granular IPv4/IPv6 allowlists enforced via nftables

⏱️ Automatic Handshake Revocation - Clients are auto-revoked after configurable inactivity periods

🌍 IP Geolocation & ISP Resolution - Optional ipstack.com integration for endpoint mapping

📡 Web Provisioning API - Secure HTTPS endpoints for self-service client configuration

🔁 Automatic DNS Updates - Seamless dnsmasq integration with auto-generated host entries on clients

## CLI Reference

### Client Management
| Command | Description |
|---------|-------------|
| `wiremand client make --domain <domain> --name <name> [--ipv4] [--public-key <BASE64>]` | Create a new client |
| `wiremand client list [--domain <domain>] [--windows-legacy]` | List active clients with handshake/endpoint status |
| `wiremand client rename <BASE64_KEY> <newname>` | Change a client's display name |
| `wiremand client provision-ipv4 --domain <domain> --name <name>` | Assign a random IPv4 to an existing client |
| `wiremand client punt --domain <domain> --name <name>` | Extend client's auto-revoke deadline |
| `wiremand client revoke --domain <domain> --name <name>` | Remove client from WG, firewall, and DNS |

### Domain Management
| Command | Description |
|---------|-------------|
| `wiremand domain make <domain>` | Create a new logical domain |
| `wiremand domain list [--api-keys]` | List domains & optional security keys |
| `wiremand domain remove <domain>` | Delete domain & all associated clients |

### Firewall Configuration
| Command | Description |
|---------|-------------|
| `wiremand firewall whitelist ipv4 --name <name> <IP1> <IP2>` | Add IPv4 allowlist entries for a client |
| `wiremand firewall whitelist ipv6 --client-v6 <CLIENT_V6> <IP1> <IP2>` | Add IPv6 allowlist entries for a client |
| `wiremand firewall blacklist ipv4 --name <name> <IP1> <IP2>` | Remove specific IPv4 entries from the whitelist |
| `wiremand firewall blacklist ipv6 --client-v6 <CLIENT_V6> <IP1> <IP2>` | Remove specific IPv6 entries from the whitelist |

### Daemon & Utilities
| Command | Description |
|---------|-------------|
| `wiremand run` | Launch daemon in foreground (debug/test) |
| `wiremand ipstack set <API_KEY>` | Configure ipstack geolocation key |
| `wiremand server add-network` | Interactively add a new IPv6 subnet to the WireGuard interface |

## Daemon Architecture
The daemon orchestrates three background services via Apple's Swift ServiceLifecycle:

| Service | Function |
|---------|----------|
| **HandshakeChecker** | Polls `wg show latest-handshakes` & `endpoints` every 10s. Updates DB, triggers IP resolution, revokes expired clients. |
| **IPStacker** | Resolves pending endpoint IPs via ipstack.com every 10m. Handles retries & stale record rotation. |
| **PublicHTTPWebServer** | Serves HTTPS provisioning API (`/wg_makekey`, `/wg_getkey`) on IPv4 & IPv6. |
