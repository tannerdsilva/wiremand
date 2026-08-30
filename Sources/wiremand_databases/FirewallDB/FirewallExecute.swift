import Foundation
import Logging

/// Builds the nft command strings for wiremand's managed firewall chains.
///
/// Pure string builders — no kernel or libnftables dependency — so the entire
/// ruleset vocabulary can be unit tested without a live host. The executable's
/// `NFTables` context executes the commands produced here.
public struct FirewallExecutor {
	public static let table = "ip_filter"

	public static let table6 = "ip6_filter"

	public static let whitelistChain = "whitelist"
	public static let domainIsolationChain = "domain_isolation"
	public static let domainTraceChain = "domain_trace"

	/// Creates the NFTable commands for creating the firewall's filter tables.
	/// These tables need to be created before running any other NFTable commands
	/// for the filter IPv4 or IPv6 table.
	public static func createIPFilters() -> [String] {
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
	public static func desiredWhitelistIPv4Rules(_ rules: [NetworkV4:[EncodedString]]) -> [String] {
		rules.flatMap { (network, ruleList) in
			ruleList.map { "ip saddr \(network.cidrstring) \(String($0))" }
		}
	}

	/// Builds the desired IPv6 whitelist rule set for the `whitelist` chain.
	public static func desiredWhitelistIPv6Rules(_ rules: [NetworkV6:[EncodedString]]) -> [String] {
		rules.flatMap { (network, ruleList) in
			ruleList.map { "ip6 saddr \(network.cidrstring) \(String($0))" }
		}
	}

	/// Builds the desired rule set for the `domain_isolation` chain (IPv4).
	public static func desiredDomainIsolationIPv4Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			domain.network.isV4
				? "ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V4: \" accept"
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_isolation` chain (IPv6).
	public static func desiredDomainIsolationIPv6Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			!domain.network.isV4
				? "ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) counter log prefix \"DOMAIN_ACCEPT_V6: \" accept"
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_trace` chain (IPv4).
	public static func desiredDomainTraceIPv4Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			domain.network.isV4
				? "ip saddr \(domain.network.cidrstring) ip daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv4)\""
				: nil
		}
	}

	/// Builds the desired rule set for the `domain_trace` chain (IPv6).
	public static func desiredDomainTraceIPv6Rules(_ domains: [WireguardDatabase.DomainInfo]) -> [String] {
		domains.compactMap { domain in
			!domain.network.isV4
				? "ip6 saddr \(domain.network.cidrstring) ip6 daddr \(domain.network.cidrstring) meta nftrace set 1 counter comment \"trace same-domain inter-client traffic (IPv6)\""
				: nil
		}
	}
}
