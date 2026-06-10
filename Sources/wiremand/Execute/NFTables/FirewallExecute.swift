import Foundation
import wiremand_databases
import Logging

struct FirewallExecutor {
	static func createDomainFirewall(domains: [WireguardDatabase.DomainInfo], interfaceName: String, wgListenPort: UInt16) -> [String] {
		var commands: [String] = []
		
		// Table and IPv6 Domain Sets
		commands.append("add table6 inet domain_firewall")
		commands.append("delete table6 inet domain_firewall")
		commands.append("add table6 inet domain_firewall")
		
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			let setElements = domain.networks.map(\.cidrstring).joined(separator: ", ")
			
			commands.append("add set inet domain_firewall \(safeName)_subnets { type ipv6_addr; flags interval; }")
			commands.append("add element inet domain_firewall \(safeName)_subnets { \(setElements) }")
		}

		commands.append("add set inet domain_firewall wg_internal_subnets { type ipv6_addr; flags interval; }")
		let setElements = domains.map{"@\($0.name)_subnets"}.joined(separator: ", ")
		commands.append("add element inet domain_firewall wg_internal_subnets { \(setElements) }")
		
		// Input Chain
		commands.append("add chain inet domain_firewall input { type filter hook input priority 0; policy drop; }")
    	commands.append("add rule inet domain_firewall input ct state established,related accept;")
    	commands.append("add rule inet domain_firewall input iifname != \"\(interfaceName)\" udp dport \(wgListenPort) accept;")
    	commands.append("add rule inet domain_firewall input iifname != \"\(interfaceName)\" tcp dport 443 ct state new accept;")
    	commands.append("add rule inet domain_firewall input iifname \"lo\" accept;")
    	commands.append("add rule inet domain_firewall input log prefix \"INPUT_DROP: \" level warn;")
		
		// Forward Chain
		commands.append("add chain inet domain_firewall forward { type filter hook forward priority 0; policy drop; }")
		commands.append("add rule inet domain_firewall forward ct state established,related accept;")
		commands.append("add rule inet domain_firewall forward iifname \"\(interfaceName)\" ip daddr != @wg_internal_subnets ct state new accept")
		commands.append("add rule inet domain_firewall forward iifname \"\(interfaceName)\" ip6 daddr != @wg_internal_subnets ct state new accept")
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			commands.append("add rule inet domain_firewall forward iifname \"\(interfaceName)\" ip6 saddr @\(safeName)_subnets ip6 daddr @\(safeName)_subnets accept;")
		}
		
		commands.append("add rule inet domain_firewall forward log prefix \"DOMAIN_ISOLATION: \" level warn;")
		commands.append("add rule inet domain_firewall forward drop;")
		
		//commands.append("add chain inet domain_firewall prerouting { type nat hook prerouting priority dstnat; policy accept; }")
		//commands.append("add rule inet domain_firewall prerouting iifname \"wl*\" tcp dport 443 dnat to 127.0.0.1:8080;")

		// commands.append("add chain inet domain_firewall postrouting { type nat hook postrouting priority srcnat; policy accept; }")
		// commands.append("add rule inet domain_firewall postrouting oifname != \"\(interfaceName)\" ip saddr @wg_internal_subnets masquerade; ")
		
		return commands
	}

	static func createWhitelist(ipv4Dictionary:[String:[String]], ipv6Dictionary:[String:[String]]) -> [String] {
		var commands: [String] = []

		let table = "ip_whitelist"

		commands.append("add table ip \(table)")
		commands.append("flush table ip \(table)")

		commands.append("add chain ip \(table) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip \(table) forward iif \"lo\" counter accept")
		commands.append("add rule ip \(table) forward ct state established,related counter accept")

		for (clientIP, whitelist) in ipv4Dictionary {
			let whitelistIPs = whitelist.joined(separator:", ")
			commands.append("add rule ip \(table) forward ct state new ip saddr \(clientIP) ip daddr { \(whitelistIPs) } counter log prefix \"WHITELIST_ACCEPT: \" accept")
		}

		let table6 = "ip6_whitelist"

		commands.append("add table ip6 \(table6)")
		commands.append("flush table ip6 \(table6)")

		commands.append("add chain ip6 \(table6) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip6 \(table6) forward iif \"lo\" counter accept")
		commands.append("add rule ip6 \(table6) forward ct state established,related counter accept")

		for (clientIP, whitelist) in ipv6Dictionary {
			let whitelistIPs = whitelist.joined(separator:", ")
			commands.append("add rule ip6 \(table6) forward ct state new ip6 saddr \(clientIP) ip6 daddr { \(whitelistIPs) } counter log prefix \"WHITELIST_ACCEPT: \" accept")
		}

		return commands
	}
}
