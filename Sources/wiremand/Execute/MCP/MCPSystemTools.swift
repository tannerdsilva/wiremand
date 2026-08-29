import MCP
import Foundation
import Logging
import QuickLMDB
import wiremand_databases

/// MCP tool: configure the ipstack API key. Mirrors `wiremand ipstack set-api-key`.
struct IPStackSetAPIKeyTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Configure the ipstack.com API key that wiremand uses for geolocation.",
name: "ipstack_set_api_key",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "key", description: "The ipstack API key", required: true, kind: .argument, typeName: "String", hasDefault: false),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)
		let key = try MCPArgs.requiredString("key", from: context)
		try deps.ipdb.setIPStackKey(key)
		return .text("IPStack API key configured")
	}
}

/// MCP tool: get the configured ipstack API key. Mirrors `wiremand ipstack get-api-key`.
struct IPStackGetAPIKeyTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Get the currently configured ipstack.com API key.",
name: "ipstack_get_api_key",
		requiredAccess: .admin
	)
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)
		do {
			let key = try deps.ipdb.getIPStackKey()
			return .text(String(key))
		} catch LMDBError.notFound {
			return .text("IPStack not configured.")
		}
	}
}

/// MCP tool: reset the server's public addresses. Mirrors `wiremand reset-public-addresses`.
/// Re-derives the default-route source addresses via netlink and stores them.
struct ResetPublicAddressesTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Re-detect the server's public IPv4 and IPv6 addresses from the default route and store them. For emergency recovery after address changes.",
name: "reset_public_addresses",
		requiredAccess: .admin
	)
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let routesV4 = try RTNetlink.getRoutesV4()
		let filteredRoutesV4 = routesV4.filter { $0.destination_length == 0 }
		guard !filteredRoutesV4.isEmpty else {
			throw MCPToolError.operationFailed("there is no default IPv4 route")
		}
		let addressesV4 = try RTNetlink.getAddressesV4()
		let filteredV4 = addressesV4.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 }
		guard let defaultV4Address = filteredV4.first!.address else {
			throw MCPToolError.operationFailed("no default IPv4 source address")
		}
		let resExtV4 = AddressV4(defaultV4Address)

		let addressesV6 = try RTNetlink.getAddressesV6()
		let filteredV6 = addressesV6.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 && !$0.flags.isTemporary }
		let resExtV6: AddressV6?
		if filteredV6.isEmpty {
			resExtV6 = AddressV6("::")
		} else {
			resExtV6 = AddressV6(filteredV6.first!.address!)
		}

		try deps.wgdb.installPublicIPAddresses(wg_resolvedServerPublicIPv4: resExtV4!, wg_resolvedServerPublicIPv6: resExtV6!)
		return .text("public addresses updated:\n  v4: \(resExtV4!.string)\n  v6: \(resExtV6!.string)")
	}
}
