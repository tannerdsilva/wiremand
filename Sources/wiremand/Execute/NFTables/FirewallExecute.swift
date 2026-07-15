import Foundation
import wiremand_databases
import Logging

struct FirewallExecutor {
	static let table = "ip_filter"

	static let table6 = "ip6_filter"

	static let whitelistChain = "whitelist"
	static let domainIsolationChain = "domain_isolation"

	static func createIPFilters() -> [String] {
		var commands: [String] = []

		// IPv4 Table
		commands.append("add table ip \(table)")
		commands.append("flush table ip \(table)")

		commands.append("add chain ip \(table) \(whitelistChain)")

		commands.append("add chain ip \(table) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip \(table) forward iif \"lo\" counter accept")
		commands.append("add rule ip \(table) forward ct state established,related counter accept")
		commands.append("add rule ip \(table) forward jump \(whitelistChain)")

		// IPv6 Table
		commands.append("add table ip6 \(table6)")
		commands.append("flush table ip6 \(table6)")

		commands.append("add chain ip6 \(table6) \(whitelistChain)")
		commands.append("add chain ip6 \(table6) \(domainIsolationChain)")

		commands.append("add chain ip6 \(table6) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip6 \(table6) forward iif \"lo\" counter accept")
		commands.append("add rule ip6 \(table6) forward ct state established,related counter accept")
		commands.append("add rule ip6 \(table6) forward jump \(whitelistChain)")
		commands.append("add rule ip6 \(table6) forward jump \(domainIsolationChain)")

		return commands
	}

	static func createDomainFirewall(domains: [WireguardDatabase.DomainInfo], interfaceName: String, wgListenPort: UInt16) -> [String] {
		var commands: [String] = []

		let table = "domain_isolation"

		commands.append("add chain ip6 \(table6) \(domainIsolationChain)")
		commands.append("flush chain ip6 \(table6) \(domainIsolationChain)")
		
		for domain in domains {
			let safeName = String(domain.name).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
			let setElements = domain.networks.map(\.cidrstring).joined(separator: ", ")
			
			commands.append("add set ip6 \(table6) \(safeName)_subnets { type ipv6_addr; flags interval; }")
			commands.append("add element ip6 \(table6) \(safeName)_subnets { \(setElements) }")

			commands.append("add rule ip6 \(table6) \(domainIsolationChain) ip6 saddr @\(safeName)_subnets ip6 daddr @\(safeName)_subnets counter log prefix \"DOMAIN_ACCEPT_\(safeName.uppercased()): \" accept")
		}
		
		return commands
	}

	/// Creates the NFTable commands for creating the client whitelist.
	/// - Parameters
	/// 	- ipv4Dictionary: The dictionary client IPv4 addresses to the array of IPv4 addresses to whitelist.
	/// 	- ipv6Dictionary: The dictionary client IPv6 addresses to the array of IPv6 addresses to whitelist.
	static func createWhitelist(ipv4Dictionary:[String:[String]], ipv6Dictionary:[String:[String]]) -> [String] {
		var commands: [String] = []

		commands.append("add chain ip \(table) \(whitelistChain)")
		commands.append("flush chain ip \(table) \(whitelistChain)")

		for (clientIP, whitelist) in ipv4Dictionary {
			let whitelistIPs = whitelist.joined(separator:", ")
			commands.append("add rule ip \(table) \(whitelistChain) ct state new ip saddr \(clientIP) ip daddr { \(whitelistIPs) } counter log prefix \"WHITELIST_ACCEPT: \" accept")
		}

		commands.append("add chain ip6 \(table6) \(whitelistChain)")
		commands.append("flush chain ip6 \(table6) \(whitelistChain)")

		for (clientIP, whitelist) in ipv6Dictionary {
			let whitelistIPs = whitelist.joined(separator:", ")
			commands.append("add rule ip6 \(table6) \(whitelistChain) ct state new ip6 saddr \(clientIP) ip6 daddr { \(whitelistIPs) } counter log prefix \"WHITELIST_ACCEPT: \" accept")
		}

		return commands
	}

	/// A function to reload the firewall (specifically for the whitelist section).
	/// The function should be called whenever a new whitelist change is added to the firewall database.
	static func reloadWhitelist(firewallDB: FirewallDatabase) throws {
		let ipv4Dict = try firewallDB.getAllWhitelistedIPv4()
		let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Dict.map { ($0.key.string, $0.value.map { $0.string }) })
		let ipv6Dict = try firewallDB.getAllWhitelistedIPv6()
		let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Dict.map { ($0.key.string, $0.value.map { $0.string }) })
		let whitelistCommands = FirewallExecutor.createWhitelist(ipv4Dictionary: ipv4Whitelist, ipv6Dictionary: ipv6Whitelist)
		let nftableExecutor = try NFTables()
		try nftableExecutor.run(commands: whitelistCommands)
	}

	// A function to reload the firewall (specifically for the domain isolation section).
	// The function should be called whenever a domain is created, a domain is destroyed, or a new server network is created.
	static func reloadDomainIsolation(wgdb: WireguardDatabase) throws {
		let domains = try wgdb.allDomains()
		let domainIPStrings = domains.map { $0.networks.map { $0.addressString } }.flatMap { $0 }
		let domainIsolationCommands = FirewallExecutor.createDomainFirewall(domains: try wgdb.allDomains(), interfaceName: String(try wgdb.primaryInterfaceName()), wgListenPort: try wgdb.getPublicListenPort().RAW_native())
		let nftableExecutor = try NFTables()
		try nftableExecutor.run(commands: domainIsolationCommands)
	}

	static func removeDomainSet(domain:String) throws {
		let nftableExecutor = try NFTables()
		let safeName = String(domain).replacingOccurrences(of: "[^a-zA-Z0-9_]", with: "_", options: .regularExpression)
		try nftableExecutor.run(commands: ["delete set ip6 \(table6) \(safeName)_subnets"])
	}
}
