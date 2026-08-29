import MCP
import Foundation
import wiremand_databases
import Logging

/// MCP tool: create a new logical domain. Mirrors `wiremand domain make`.
struct DomainMakeTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Create a new logical domain with a subnet. Returns the domain security key (sk), domain key (dk) and the subnet.",
name: "domain_make",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "subnet", description: "The v4 or v6 subnet CIDR to assign to the domain. If omitted, a random fd00::/8 ULA /64 is generated.", required: false, kind: .option, typeName: "String", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let domainName = try MCPArgs.requiredString("domain", from: context).lowercased()
		let subnetInput = MCPArgs.optionalString("subnet", from: context)

		let ipScope: wiremand_databases.Network
		if let subnetInput {
			guard let parsedNetwork = wiremand_databases.Network(subnetInput) else {
				return .error("invalid subnet: \(subnetInput)")
			}
			ipScope = parsedNetwork
		} else {
			ipScope = wiremand_databases.Network(Self.randomULAIPv6Subnet())!
		}

		let interfaceName = try deps.wgdb.primaryInterfaceName()
		let newSK = try deps.wgdb.domainMake(name: EncodedString(domainName), subnet: ipScope)
		try await WireguardExecutor.installDomain(subnet: ipScope, interfaceName: interfaceName)
		try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		let domainHash = try DomainHash(domainName: EncodedString(domainName))
		try FirewallExecutor.reloadDomainIsolation(wgdb: deps.wgdb, firewallDB: deps.firewallDB)
		return .text("domain created: \(domainName)\nsk: \(newSK.string)\ndk: \(domainHash.string)\nsubnet: \(ipScope.cidrstring)")
	}

	/// RFC 4193 style ULA: fd + 40-bit global ID + 16-bit subnet, /64.
	/// Mirrors the CLI default.
	private static func randomULAIPv6Subnet() -> String {
		var bytes = [UInt8](repeating: 0, count: 8)
		for i in 1..<8 { bytes[i] = UInt8.random(in: 0...255) }
		bytes[0] = 0xfd
		let hextet0 = String(format: "%02x%02x", bytes[0], bytes[1])
		let hextet1 = String(format: "%02x%02x", bytes[2], bytes[3])
		let hextet2 = String(format: "%02x%02x", bytes[4], bytes[5])
		let hextet3 = String(format: "%02x%02x", bytes[6], bytes[7])
		return "\(hextet0):\(hextet1):\(hextet2):\(hextet3)::/64"
	}
}

/// MCP tool: list the configured domains. Mirrors `wiremand domain list`.
struct DomainListTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "List the domains configured on this server.",
name: "domain_list",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "include_api_keys", description: "Include the domain security key (sk) and domain key (dk)", required: false, kind: .flag, typeName: "Bool", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let showKeys = MCPArgs.boolFlag("include_api_keys", from: context)
		let allDomains = try deps.wgdb.allDomains()
		var lines: [String] = []
		for currentDomain in allDomains {
			var entry = String(currentDomain.name)
			entry += "\n  subnet: \(currentDomain.network.cidrstring)"
			if showKeys {
				entry += "\n  sk: \(currentDomain.securityKey.string)"
				entry += "\n  dk: \((try DomainHash(domainName: currentDomain.name)).string)"
			}
			lines.append(entry)
		}
		return .text(lines.joined(separator: "\n"))
	}
}
