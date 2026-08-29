import MCP
import Foundation
import Logging
import QuickLMDB
import bedrock_ip
import wiremand_databases

/// MCP tool: add a firewall rule to a domain. Mirrors `wiremand firewall add-rule`.
struct FirewallAddRuleTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Add a firewall whitelist rule for a domain. The rule is validated against nftables before being persisted. The verdict must not be drop.",
name: "firewall_add_rule",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "network", description: "The domain subnet CIDR (alternative to name)", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "name", description: "The domain name (alternative to network)", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "rule", description: "The nftables rule fragment, e.g. 'tcp dport 22 accept'", required: true, kind: .argument, typeName: "String", hasDefault: false),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let networkInput = MCPArgs.optionalString("network", from: context)
		let nameInput = MCPArgs.optionalString("name", from: context)
		guard networkInput != nil || nameInput != nil else {
			return .error("provide either 'network' or 'name'")
		}
		let allDomains = try deps.wgdb.allDomains()
		let resolvedNetwork: wiremand_databases.Network
		if let networkInput {
			guard let parsedNetwork = wiremand_databases.Network(networkInput),
				allDomains.contains(where: { $0.network.cidrstring == parsedNetwork.cidrstring }) else {
				return .error("network does not correspond to any domain")
			}
			resolvedNetwork = parsedNetwork
		} else if let nameInput {
			guard let domain = allDomains.first(where: { String($0.name) == nameInput }) else {
				return .error("domain '\(nameInput)' not found")
			}
			resolvedNetwork = domain.network
		} else {
			return .error("provide either 'network' or 'name'")
		}

		let ruleInput = try MCPArgs.requiredString("rule", from: context)
		let family = resolvedNetwork.isV4 ? "ip" : "ip6"
		let validationCommands = [
			"add table \(family) testTable",
			"add chain \(family) testTable testChain",
			"add rule \(family) testTable testChain \(family) saddr \(resolvedNetwork.cidrstring) \(ruleInput)",
			"delete table \(family) testTable",
		]
		do {
			let nftableExecutor = try NFTables()
			try nftableExecutor.run(commands: validationCommands)
		} catch {
			return .error("invalid rule syntax: \(ruleInput)")
		}

		let rule = EncodedString(ruleInput)
		if resolvedNetwork.isV4 {
			try deps.firewallDB.addDomainV4Rule(domain: NetworkV4(resolvedNetwork.cidrstring)!, rule: rule)
		} else {
			try deps.firewallDB.addDomainV6Rule(domain: NetworkV6(resolvedNetwork.cidrstring)!, rule: rule)
		}
		try FirewallExecutor.reloadWhitelist(firewallDB: deps.firewallDB)
		return .text("firewall rule added to \(resolvedNetwork.cidrstring)")
	}
}

/// MCP tool: delete all firewall rules for a domain. Mirrors `wiremand firewall delete-rules`.
struct FirewallDeleteRulesTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Delete all firewall rules for a given domain.",
name: "firewall_delete_rules",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "network", description: "The domain subnet CIDR (alternative to name)", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "name", description: "The domain name (alternative to network)", required: false, kind: .option, typeName: "String", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let networkInput = MCPArgs.optionalString("network", from: context)
		let nameInput = MCPArgs.optionalString("name", from: context)
		guard networkInput != nil || nameInput != nil else {
			return .error("provide either 'network' or 'name'")
		}
		let allDomains = try deps.wgdb.allDomains()
		let resolvedNetwork: wiremand_databases.Network
		if let networkInput {
			guard let parsedNetwork = wiremand_databases.Network(networkInput),
				allDomains.contains(where: { $0.network.cidrstring == parsedNetwork.cidrstring }) else {
				return .error("network does not correspond to any domain")
			}
			resolvedNetwork = parsedNetwork
		} else if let nameInput {
			guard let domain = allDomains.first(where: { String($0.name) == nameInput }) else {
				return .error("domain '\(nameInput)' not found")
			}
			resolvedNetwork = domain.network
		} else {
			return .error("provide either 'network' or 'name'")
		}

		do {
			try deps.firewallDB.deleteDomainRules(domain: bedrock_ip.Network(resolvedNetwork.cidrstring)!)
		} catch LMDBError.notFound {
			// no rules to delete
		}
		try FirewallExecutor.reloadWhitelist(firewallDB: deps.firewallDB)
		return .text("firewall rules removed for \(resolvedNetwork.cidrstring)")
	}
}

/// MCP tool: list the active domain firewall rules. Mirrors `wiremand firewall list`.
struct FirewallListTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "List the active domain firewall rules.",
name: "firewall_list",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "name", description: "Only list rules for this domain", required: false, kind: .option, typeName: "String", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let ipv4Rules = try deps.firewallDB.getIPv4Rules()
		let ipv6Rules = try deps.firewallDB.getIPv6Rules()
		let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
		var allRules = ipv4Whitelist.merging(ipv6Whitelist) { _, newValue in newValue }

		let allDomains = try deps.wgdb.allDomains()
		if let nameInput = MCPArgs.optionalString("name", from: context) {
			guard let domain = allDomains.first(where: { String($0.name) == nameInput }) else {
				return .error("domain '\(nameInput)' not found")
			}
			allRules = Dictionary(uniqueKeysWithValues: allRules.filter { $0.key == domain.network.cidrstring })
		}

		var lines: [String] = []
		for (network, rules) in allRules {
			guard let domain = allDomains.first(where: { $0.network.cidrstring == network }) else { continue }
			var entry = String(domain.name)
			if rules.isEmpty {
				entry += "\n  (no rules)"
			} else {
				for rule in rules {
					entry += "\n  - \(rule)"
				}
			}
			lines.append(entry)
		}
		return .text(lines.joined(separator: "\n"))
	}
}
