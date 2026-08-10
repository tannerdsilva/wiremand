import Foundation
import wiremand_databases
import Logging

struct FirewallExecutor {
	static let table = "ip_filter"

	static let table6 = "ip6_filter"

	static let whitelistChain = "whitelist"
	static let domainIsolationChain = "domain_isolation"
	static let domainTraceChain = "domain_trace"

	/// Creates the NFTable commands for creating the firewall's filter tables.
	/// These tables need to be created before running any other NFTable commands
	/// for the filter IPv4 or IPv6 table.
	static func createIPFilters() -> [String] {
		var commands: [String] = []

		// IPv4 Table
		commands.append("add table ip \(table)")
		commands.append("flush table ip \(table)")

		commands.append("add chain ip \(table) \(whitelistChain)")
		commands.append("add chain ip \(table) \(domainIsolationChain)")
		commands.append("add chain ip \(table) \(domainTraceChain)")

		commands.append("add chain ip \(table) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip \(table) forward iif \"lo\" counter accept")
		commands.append("add rule ip \(table) forward ct state established,related counter accept")
		// Jump the same-domain trace chain before the whitelist/isolation chains so that
		// inter-client traffic within a domain has its nftrace flag set at the top of the
		// forward path. This makes the full rule walk visible via `nft monitor trace`.
		commands.append("add rule ip \(table) forward jump \(domainTraceChain)")
		commands.append("add rule ip \(table) forward jump \(whitelistChain)")
		commands.append("add rule ip \(table) forward jump \(domainIsolationChain)")

		// IPv6 Table
		commands.append("add table ip6 \(table6)")
		commands.append("flush table ip6 \(table6)")

		commands.append("add chain ip6 \(table6) \(whitelistChain)")
		commands.append("add chain ip6 \(table6) \(domainIsolationChain)")
		commands.append("add chain ip6 \(table6) \(domainTraceChain)")

		commands.append("add chain ip6 \(table6) forward { type filter hook forward priority filter; policy drop; }")
		commands.append("add rule ip6 \(table6) forward iif \"lo\" counter accept")
		commands.append("add rule ip6 \(table6) forward ct state established,related counter accept")
		// See the IPv4 comment above: same-domain traffic is traced before the
		// whitelist/isolation chains are evaluated.
		commands.append("add rule ip6 \(table6) forward jump \(domainTraceChain)")
		commands.append("add rule ip6 \(table6) forward jump \(whitelistChain)")
		commands.append("add rule ip6 \(table6) forward jump \(domainIsolationChain)")

		return commands
	}

	/// Creates the NFTable commands for domain isolation.
	/// Domain isolation is updated automatically according to the servers domains.
	/// - Parameters
	/// 	- domains: The array of domains to isolate.
	static func createDomainFirewall(domains: [WireguardDatabase.DomainInfo]) -> [String] {
		var commands: [String] = []

		// Set up the same-domain trace chain for both families. It is flushed and rebuilt
		// on every reload (like the isolation chain) so it always reflects the live domain
		// list and never accumulates stale rules for removed domains.
		commands.append("add chain ip6 \(table6) \(domainTraceChain)")
		commands.append("flush chain ip6 \(table6) \(domainTraceChain)")

		commands.append("add chain ip \(table) \(domainTraceChain)")
		commands.append("flush chain ip \(table) \(domainTraceChain)")

		commands.append("add chain ip6 \(table6) \(domainIsolationChain)")
		commands.append("flush chain ip6 \(table6) \(domainIsolationChain)")

		commands.append("add chain ip \(table) \(domainIsolationChain)")
		commands.append("flush chain ip \(table) \(domainIsolationChain)")
		
		for domain in domains {
			if (domain.network.isV4) {
				commands.append("add rule ip \(table) \(domainIsolationChain) ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V4: \" accept")
				commands.append("add rule ip \(table) \(domainTraceChain) ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv4)\"")
			} else {
				commands.append("add rule ip6 \(table6) \(domainIsolationChain) ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V6: \" accept")
				commands.append("add rule ip6 \(table6) \(domainTraceChain) ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv6)\"")
			}
		}
		
		return commands
	}

	/// Creates the NFTable commands for creating the domain whitelist.
	/// - Parameters
	/// 	- ipv4Rules: The dictionary of IPv4 domains to nft rules.
	/// 	- ipv6Rules: The dictionary of IPv6 domains to nft rules.
	static func createWhitelist(ipv4Rules:[String:[String]], ipv6Rules:[String:[String]]) -> [String] {
		var commands: [String] = []

		commands.append("add chain ip \(table) \(whitelistChain)")
		commands.append("flush chain ip \(table) \(whitelistChain)")

		for (domain, rules) in ipv4Rules {
			for rule in rules {
				commands.append("add rule ip \(table) \(whitelistChain) ip saddr \(domain) \(rule)")
			}
		}

		commands.append("add chain ip6 \(table6) \(whitelistChain)")
		commands.append("flush chain ip6 \(table6) \(whitelistChain)")

		for (domain, rules) in ipv6Rules {
			for rule in rules {
				commands.append("add rule ip6 \(table6) \(whitelistChain) ip6 saddr \(domain) \(rule)")
			}
		}

		return commands
	}

	/// A function to reload the firewall (specifically for the whitelist section).
	/// The function should be called whenever a new whitelist change is added to the firewall database.
	static func reloadWhitelist(firewallDB: FirewallDatabase) throws {
		let ipv4Rules = try firewallDB.getIPv4Rules()
		let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		let ipv6Rules = try firewallDB.getIPv6Rules()
		let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		let whitelistCommands = FirewallExecutor.createWhitelist(ipv4Rules:ipv4Whitelist, ipv6Rules:ipv6Whitelist)
		let nftableExecutor = try NFTables()
		try nftableExecutor.run(commands: whitelistCommands)
	}

	// A function to reload the firewall (specifically for the domain isolation section).
	// The function should be called whenever a domain is created, a domain is destroyed, or a new server network is created.
	static func reloadDomainIsolation(wgdb: WireguardDatabase) throws {
		let domainIsolationCommands = FirewallExecutor.createDomainFirewall(domains: try wgdb.allDomains())
		let nftableExecutor = try NFTables()
		try nftableExecutor.run(commands: domainIsolationCommands)
	}
}
