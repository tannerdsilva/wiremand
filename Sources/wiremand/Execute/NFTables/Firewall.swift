import Foundation
import wiremand_databases
import Logging

struct Firewall {
	static func createDomainFirewall(domains: [WireguardDatabase.DomainInfo]) -> [String] {
		var commands: [String] = []
		
		commands.append("flush table inet domain_firewall")
		commands.append("add table inet domain_firewall")
		
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			let setElements = domain.networks.map(\.cidrstring).joined(separator: ", ")
			
			commands.append("add set inet domain_firewall \(safeName)_subnets { type ipv6_addr; flags interval; }")
			commands.append("add element inet domain_firewall \(safeName)_subnets { \(setElements) }")
		}
		
		commands.append("add chain inet domain_firewall input { type filter hook input priority 0; policy drop; }")
		commands.append("add rule inet domain_firewall input ct state established,related accept;")
		
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			commands.append("add rule inet domain_firewall input ip6 saddr @\(safeName)_subnets ip6 daddr @\(safeName)_subnets accept;")
		}
		
		commands.append("add rule inet domain_firewall input log prefix \"DOMAIN_ISOLATION: \" level warn;")
		commands.append("add rule inet domain_firewall input drop;")
		
		commands.append("add chain inet domain_firewall forward { type filter hook forward priority 0; policy drop; }")
		commands.append("add rule inet domain_firewall forward ct state established,related accept;")
		
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			commands.append("add rule inet domain_firewall forward ip6 saddr @\(safeName)_subnets ip6 daddr @\(safeName)_subnets accept;")
		}
		
		commands.append("add rule inet domain_firewall forward log prefix \"DOMAIN_ISOLATION: \" level warn;")
		commands.append("add rule inet domain_firewall forward drop;")
		
		return commands
	}
}
