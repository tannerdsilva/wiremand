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

	/// Builds the desired IPv4 whitelist rule set for the `whitelist` chain.
	/// Each entry is a full rule expression (after the chain name) matching the
	/// source address of a domain, e.g. `ip saddr 10.0.0.0/24 tcp dport 22 accept`.
	static func desiredWhitelistIPv4Rules(_ rules: [NetworkV4:[EncodedString]]) -> [String] {
		rules.flatMap { (network, ruleList) in
			ruleList.map { "ip saddr \(network.cidrstring) \(String($0))" }
		}
	}

	/// Builds the desired IPv6 whitelist rule set for the `whitelist` chain.
	static func desiredWhitelistIPv6Rules(_ rules: [NetworkV6:[EncodedString]]) -> [String] {
		rules.flatMap { (network, ruleList) in
			ruleList.map { "ip6 saddr \(network.cidrstring) \(String($0))" }
		}
	}

	/// Builds the desired rule set for the `domain_isolation` chain (IPv4).
	static func desiredDomainIsolationIPv4Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			domain.network.isV4
				? "ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V4: \" accept"
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_isolation` chain (IPv6).
	static func desiredDomainIsolationIPv6Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			!domain.network.isV4
				? "ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V6: \" accept"
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_trace` chain (IPv4).
	static func desiredDomainTraceIPv4Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			domain.network.isV4
				? "ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv4)\""
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_trace` chain (IPv6).
	static func desiredDomainTraceIPv6Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			!domain.network.isV4
				? "ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv6)\""
				: nil
		}
	}

	/// A function to reload the firewall (specifically for the whitelist section).
	/// The function should be called whenever a new whitelist change is added to the firewall database.
	/// Incrementally reconciles the `whitelist` chain: unchanged rules are left
	/// untouched, newly added rules are appended, and only removals trigger a
	/// scoped re-render of the chain.
	static func reloadWhitelist(firewallDB: FirewallDatabase) throws {
		var log = Logger(label: "firewall-whitelist")
		let ipv4Rules = try firewallDB.getIPv4Rules()
		let ipv6Rules = try firewallDB.getIPv6Rules()

		let nft = try NFTables()
		try FirewallSync.sync(
			family: "ip", table: table, chain: whitelistChain,
			desired: desiredWhitelistIPv4Rules(ipv4Rules), force: false,
			runner: nft, store: firewallDB, logger: log
		)
		try FirewallSync.sync(
			family: "ip6", table: table6, chain: whitelistChain,
			desired: desiredWhitelistIPv6Rules(ipv6Rules), force: false,
			runner: nft, store: firewallDB, logger: log
		)
	}

	// A function to reload the firewall (specifically for the domain isolation and trace sections).
	// The function should be called whenever a domain is created, a domain is destroyed, or a new server network is created.
	// Incrementally reconciles the `domain_isolation` and `domain_trace` chains.
	static func reloadDomainIsolation(wgdb: WireguardDatabase, firewallDB: FirewallDatabase) throws {
		var log = Logger(label: "firewall-domain-isolation")
		let domains = try wgdb.allDomains()

		let nft = try NFTables()
		try FirewallSync.sync(
			family: "ip", table: table, chain: domainIsolationChain,
			desired: desiredDomainIsolationIPv4Rules(domains), force: false,
			runner: nft, store: firewallDB, logger: log
		)
		try FirewallSync.sync(
			family: "ip6", table: table6, chain: domainIsolationChain,
			desired: desiredDomainIsolationIPv6Rules(domains), force: false,
			runner: nft, store: firewallDB, logger: log
		)
		try FirewallSync.sync(
			family: "ip", table: table, chain: domainTraceChain,
			desired: desiredDomainTraceIPv4Rules(domains), force: false,
			runner: nft, store: firewallDB, logger: log
		)
		try FirewallSync.sync(
			family: "ip6", table: table6, chain: domainTraceChain,
			desired: desiredDomainTraceIPv6Rules(domains), force: false,
			runner: nft, store: firewallDB, logger: log
		)
	}
}
