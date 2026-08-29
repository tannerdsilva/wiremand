# Wiremand

**A secure, low-overhead WireGuard server management daemon & CLI for Linux**

## Overview

Wiremand is a Swift-based command-line tool and systemd daemon designed to automate the lifecycle management of WireGuard VPN configurations. It handles client provisioning, automatic revocation, domain segmentation, firewall whitelisting, DNS integration, and geolocation tracking via a single cohesive interface.

## Features

🔑 Client Lifecycle Management - Create, list, rename, modify, and revoke clients

🌐 Domain Segmentation - Partition clients into isolated logical domains with dedicated security keys

🛡️ Per-Client Firewall Whitelisting - Granular domain allowlisting enforced via nftables

⏱️ Automatic Handshake Revocation - Clients are auto-revoked after configurable inactivity periods

🌍 IP Geolocation & ISP Resolution - Optional ipstack.com integration for client endpoint mapping

📡 Web Provisioning API - Secure HTTPS endpoints for self-service client configuration

🤖 Internal MCP Admin Server - The full CLI command surface (except `install`/`update`/`run`/`domain remove`) over the authenticated VPN tunnel via MCP, gated per public key for admin-grade control

🔁 Automatic DNS Updates - Seamless dnsmasq integration with auto-generated host entries on clients

## Install/Setup

Install nftables `apt-get install libnftables-dev`. Swift build wiremand and run the install CLI command. Reboot the machine.

Edit the stubby file. `nano /etc/stubby/stubby.yml` (or your text editor of choosing) and change the Listen Address to

    listen_addresses:
    - 127.0.0.1@5353
    - 0::1@5353

Save the changes. Then run `systemctl restart stubby` and `systemctl restart dnsmasq`.

## Public API

Creating a new key via the public webserver: `curl -k -X POST "https://serverPublicIP:8080/wg_makekey?sk=...&domain=...&dk=...&key_name=...&client_public_key=...`

Getting a key that has been created on the server: `curl -k "https://serverPublicIP:8080/wg_getkey?domain=...&dk=...&pk=...`

## CLI Reference

### Client Management
| Command | Description |
|---------|-------------|
| `wiremand client make --domain <domain> --name <name> [--public-key <BASE64>]` | Create a new client |
| `wiremand client list [--domain <domain>] [--windows-legacy]` | List active clients with handshake/endpoint status |
| `wiremand client rename <BASE64_KEY> <newname>` | Change a client's display name |
| `wiremand client add-domain --domain <domain> --name <name> [--public-key <BASE64>]` | Assign an ip address to a client in a domain (identify by `--name` or, deterministically, `--public-key`) |
| `wiremand client remove-domain --domain <domain> --name <name> [--public-key <BASE64>]` | Remove a client from a domain (same identification options; revokes if it was the only domain) |
| `wiremand client mcp-access --domain <domain> --name <name> --grant\|--revoke` | Grant or revoke access to the internal MCP admin server |
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
| `wiremand reset-public-addresses` | Reset public addresses post installer |

## Daemon Architecture
The daemon orchestrates five services via Apple's Swift ServiceLifecycle under one `ServiceGroup` (graceful shutdown on SIGTERM/SIGINT). The firewall is declared first so it is torn down last, after the traffic-serving services stop.

| Service | Function |
|---------|----------|
| **FirewallService** | Renders the managed nftables ruleset (whitelist, domain isolation, trace) on start and deletes its tables on graceful shutdown. |
| **HandshakeChecker** | Polls `wg show latest-handshakes` & `endpoints` every 10s. Updates DB, triggers IP resolution, revokes expired clients. |
| **IPStacker** | Resolves pending endpoint IPs via ipstack.com every 10m. Handles retries & stale record rotation. |
| **PublicHTTPWebServer** | Serves HTTPS provisioning API (`/wg_makekey`, `/wg_getkey`) on public IPv4 & IPv6 addresses. |
| **MCPAdminServer** | Serves the internal MCP admin API bound to the server's own wireguard interface address (port 8095 by default, `wiremand run --mcp-port`). Reachable only through the authenticated tunnel. |

### Internal MCP admin server

A granted client can drive the full CLI surface over MCP (domain/client/firewall/ipstack management plus `reset-public-addresses`; `install`/`update`/`run` and `domain remove` are deliberately absent). Authorization is layered:

1. **Transport** - the server binds only to the wireguard interface address; nothing is exposed on public interfaces.
2. **Accept time** - the connection's source address is reverse-mapped to a client public key and must hold the MCP grant bit; unknown/non-granted peers see zero tools.
3. **Per call** - every tool re-checks the caller's grant at each invocation, so revoking access takes effect immediately on already-open connections.

Administrators grant access per key: `wiremand client mcp-access --domain <domain> --name <name> --grant` (revoke with `--revoke`). `client list` marks granted keys with `[mcp]`.
