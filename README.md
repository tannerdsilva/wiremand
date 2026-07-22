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

## Install/Setup

Install nftables `apt-get install libnftables-dev`. Swift build wiremand. Reboot the machine.

Edit the stubby file. `nano /etc/stubby/stubby.yml` (or your text editor of choosing) and change the Listen Address to

    listen_addresses:
    - 127.0.0.1@5353
    - 0::1@5353

Save the changes. Then run `systemctl restart stubby`

## Public API

Creating a new key via the public webserver: `curl -k -X POST "https://serverPublicIP:8080/wg_makekey?sk=...&domain=...&dk=...&key_name=...&client_public_key=...`

Getting a key that has been created on the server: `curl -k "https://serverPublicIP:8080/wg_getkey?domain=...&dk=...&pk=...`

## CLI Reference

### Client Management
| Command | Description |
|---------|-------------|
| `wiremand client make --domain <domain> --name <name> [--ipv4] [--public-key <BASE64>]` | Create a new client |
| `wiremand client list [--domain <domain>] [--windows-legacy]` | List active clients with handshake/endpoint status |
| `wiremand client rename <BASE64_KEY> <newname>` | Change a client's display name |
| `wiremand client provision-ip <BASE64_KEY> <domain>` | Assign an ip address to a client in a domain |
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
| `wiremand firewall add-rule [--network <network>] [--name <name>]` | Add firewall rule to the specified network |
| `wiremand firewall delete-rules [--network <network>] [--name <name>]` | Deletes all firewall rules for a domain |
| `wiremand firewall list [--name <name>]` | Lists all firewall rules |

### Daemon & Utilities
| Command | Description |
|---------|-------------|
| `wiremand run` | Launch daemon in foreground (debug/test) |
| `wiremand ipstack set-api-key <API_KEY>` | Configure ipstack api key |
| `wiremand ipstack get-api-key` | Get ipstack api key |

## Daemon Architecture
The daemon orchestrates three background services via Apple's Swift ServiceLifecycle:

| Service | Function |
|---------|----------|
| **HandshakeChecker** | Polls `wg show latest-handshakes` & `endpoints` every 10s. Updates DB, triggers IP resolution, revokes expired clients. |
| **IPStacker** | Resolves pending endpoint IPs via ipstack.com every 10m. Handles retries & stale record rotation. |
| **PublicHTTPWebServer** | Serves HTTPS provisioning API (`/wg_makekey`, `/wg_getkey`) on public IPv4 & IPv6 addresses. |
