import Foundation
import Logging
import wiremand_databases

// Live-reload entry points for the firewall. These are the only firewall
// commands that require a real kernel context (the executable's `NFTables`),
// so they live here rather than in wiremand_databases' pure command builders.
extension FirewallExecutor {
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
