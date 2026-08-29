import MCP
import Foundation
import Logging
import QuickLMDB
import bedrock
import bedrock_ip
import wiremand_databases

/// MCP tool: create a new client. Mirrors `wiremand client make`.
struct ClientMakeTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Create a new client in a domain and install it on the wireguard interface. Returns the client's wireguard configuration.",
name: "client_make",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "name", description: "The client name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "public_key", description: "An existing wireguard public key to use; if omitted a new keypair is generated", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "no_dns", description: "Do not include DNS instructions in the generated configuration", required: false, kind: .flag, typeName: "Bool", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let domainName = EncodedString(try MCPArgs.requiredString("domain", from: context).lowercased())
		let clientName = EncodedString(try MCPArgs.requiredString("name", from: context))
		let publicKeyInput = MCPArgs.optionalString("public_key", from: context)
		let noDNS = MCPArgs.boolFlag("no_dns", from: context)

		guard try deps.wgdb.validateNewClientName(domain: domainName, clientName: clientName) == true else {
			return .error("the client name '\(String(clientName))' cannot be used")
		}

		let newKeys = try await WireguardExecutor.generateClient()
		let usePublicKey: PublicKey
		if let publicKeyInput {
			guard let parsedPublicKey = PublicKey(argument: publicKeyInput) else {
				return .error("provided public_key is not a valid wireguard public key")
			}
			usePublicKey = parsedPublicKey
		} else {
			usePublicKey = newKeys.publicKey
		}

		let address: wiremand_databases.Address
		do {
			address = try deps.wgdb.clientMake(name: clientName, publicKey: usePublicKey, domain: domainName)
		} catch LMDBError.keyExists {
			return .error("a client named '\(String(clientName))' already exists in domain '\(String(domainName))'")
		}

		let (wgPort, wgPrimarySubnet, pubKey, interfaceName, ipv4Public, _) = try deps.wgdb.getWireguardConfigMetas()

		var buildKey = "[Interface]\n"
		if publicKeyInput == nil {
			buildKey += "PrivateKey = \(newKeys.privateKey)\n"
		}
		buildKey += "Address = \(address.string)\n"
		if noDNS == false {
			buildKey += "DNS = \(wgPrimarySubnet.addressString)\n"
		}
		buildKey += "[Peer]\n"
		buildKey += "PublicKey = \(pubKey.string)\n"
		buildKey += "PresharedKey = \(newKeys.presharedKey)\n"
		if address.isV4 {
			let ipAddressSubnet = String(bedrock_ip.AddressV4(subnetPrefix: 24)! & bedrock_ip.AddressV4(address.string)!) + "/24"
			buildKey += "AllowedIPs = \(ipAddressSubnet)\n"
		} else {
			let ipAddressSubnet = String(bedrock_ip.AddressV6(subnetPrefix: 64)! & bedrock_ip.AddressV6(address.string)!) + "/64"
			buildKey += "AllowedIPs = \(ipAddressSubnet)\n"
		}
		let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
		buildKey += "AllowedIPs = \(dnsAllowedIPString)"
		buildKey += "Endpoint = \(ipv4Public.string):\(wgPort.RAW_native())\n"
		buildKey += "PersistentKeepalive = 25\n"

		try await WireguardExecutor.install(publicKey: usePublicKey, presharedKey: newKeys.presharedKey, addresses: [address], interfaceName: interfaceName)
		try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		try deps.wgdb.serveConfiguration(EncodedString(buildKey), forPublicKey: usePublicKey)
		try DNSmasqExecutor.exportAutomaticDNSEntries(db: deps.wgdb)
		try await DNSmasqExecutor.reload()

		return .text(buildKey)
	}
}

/// MCP tool: list clients. Mirrors `wiremand client list`.
struct ClientListTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "List the clients authorized to connect to this server, grouped by domain.",
name: "client_list",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "Only list clients in this domain", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "windows_legacy", description: "Render IPv6 addresses in the Windows ipv6-literal.net format", required: false, kind: .flag, typeName: "Bool", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let windowsLegacy = MCPArgs.boolFlag("windows_legacy", from: context)
		let domainFilter: EncodedString?
		if let domainInput = MCPArgs.optionalString("domain", from: context) {
			domainFilter = EncodedString(domainInput.lowercased())
		} else {
			domainFilter = nil
		}

		let allClients: Set<WireguardDatabase.ClientInfo>
		if let domainFilter {
			allClients = try deps.wgdb.allClients(domain: domainFilter)
		} else {
			allClients = try deps.wgdb.allClients()
		}

		var domainGroup: [EncodedString: [WireguardDatabase.ClientInfo]] = [:]
		for client in allClients {
			for domainName in client.domains.keys {
				domainGroup[domainName, default: []].append(client)
			}
		}
		let nowDate = bedrock.Date.Seconds()

		var lines: [String] = []
		for (domainName, clients) in domainGroup.sorted(by: { $0.key < $1.key }) {
			lines.append(String(domainName))
			for client in clients.sorted(by: { $0.name < $1.name }) {
				var entry = "  - \(String(client.name))"
				if let domainAddress = client.domains[domainName] {
					if windowsLegacy {
						entry += "\n      \(domainAddress.string.replacingOccurrences(of: ":", with: "-") + ".ipv6-literal.net")"
					} else {
						entry += "\n      \(domainAddress.string)"
					}
				}
				if let lastHandshake = client.lastHandshake {
					entry += "\n      last handshake: \(lastHandshake.relativeTimeString(to: nowDate).lowercased())"
					if let hasEndpoint = client.endpoint {
						entry += "\n      endpoint: \(hasEndpoint)"
					}
				} else {
					entry += "\n      never handshaken"
				}
				entry += "\n      public key: \(client.publicKey.string)"
				if (try? deps.wgdb.hasMCPAccess(publicKey: client.publicKey)) == true {
					entry += "\n      mcp access: granted"
				}
				lines.append(entry)
			}
		}
		return .text(lines.joined(separator: "\n"))
	}
}

/// MCP tool: rename a client. Mirrors `wiremand client rename`.
struct ClientRenameTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Rename an existing client within its domain.",
name: "client_rename",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "public_key", description: "The base64 wireguard public key of the client", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "new_name", description: "The new client name", required: true, kind: .argument, typeName: "String", hasDefault: false),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let publicKeyString = try MCPArgs.requiredString("public_key", from: context)
		guard let publicKey = PublicKey(argument: publicKeyString) else {
			return .error("public_key is not a valid wireguard public key")
		}
		let newName = EncodedString(try MCPArgs.requiredString("new_name", from: context))

		try deps.wgdb.clientRename(publicKey: publicKey, name: newName)
		try DNSmasqExecutor.exportAutomaticDNSEntries(db: deps.wgdb)
		try await DNSmasqExecutor.reload()
		return .text("client renamed to \(String(newName))")
	}
}

/// MCP tool: revoke a client. Mirrors `wiremand client revoke`.
struct ClientRevokeTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Revoke a client and prevent it from connecting to this server.",
name: "client_revoke",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "name", description: "The client name", required: true, kind: .argument, typeName: "String", hasDefault: false),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let domainName = EncodedString(try MCPArgs.requiredString("domain", from: context).lowercased())
		let clientName = EncodedString(try MCPArgs.requiredString("name", from: context))
		let interfaceName = try deps.wgdb.primaryInterfaceName()

		let removedClientKey = try deps.wgdb.clientRemove(domain: domainName, name: clientName)
		try await WireguardExecutor.uninstall(publicKey: removedClientKey, interfaceName: interfaceName)
		try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		try DNSmasqExecutor.exportAutomaticDNSEntries(db: deps.wgdb)
		try await DNSmasqExecutor.reload()
		return .text("client revoked: \(removedClientKey.string)")
	}
}

/// MCP tool: punt a client's auto-revoke date. Mirrors `wiremand client punt`.
struct ClientPuntTool: MCPTool {
	static let configuration = MCPToolConfiguration(
				description: "Push a client's auto-revoke deadline into the future.",
name: "client_punt",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "name", description: "The client name", required: true, kind: .argument, typeName: "String", hasDefault: false),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let domainName = EncodedString(try MCPArgs.requiredString("domain", from: context).lowercased())
		let clientName = EncodedString(try MCPArgs.requiredString("name", from: context))
		let newInvalidDate = try deps.wgdb.puntClientInvalidation(domain: domainName, name: clientName)
		return .text("client punted to \(newInvalidDate.iso8601String())")
	}
}

/// MCP tool: add a client to another domain. Mirrors `wiremand client add-domain`.
struct ClientAddDomainTool: MCPTool {
	static let configuration = MCPToolConfiguration(
		description: "Add a client to another domain.",
		name: "client_add_domain",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The target domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "name", description: "The client name (required unless public_key is provided)", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "public_key", description: "The client's base64 wireguard public key (required unless name is provided)", required: false, kind: .option, typeName: "String", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let targetDomain = EncodedString(try MCPArgs.requiredString("domain", from: context).lowercased())
		let clientNameInput = MCPArgs.optionalString("name", from: context)
		let publicKeyInput = MCPArgs.optionalString("public_key", from: context)
		guard publicKeyInput != nil || clientNameInput != nil else {
			return .error("provide either 'name' or 'public_key'")
		}
		let (_, _, _, interfaceName, _, _) = try deps.wgdb.getWireguardConfigMetas()

		let clientInfo: WireguardDatabase.ClientInfo
		if let publicKeyInput {
			guard let clientKey = PublicKey(argument: publicKeyInput) else {
				return .error("public_key is not a valid wireguard public key")
			}
			_ = try deps.wgdb.clientAssignDomain(domain: targetDomain, publicKey: clientKey)
			guard let resolved = try deps.wgdb.allClients().first(where: { $0.publicKey == clientKey }) else {
				throw MCPToolError.notFound("client \(clientKey.string)")
			}
			clientInfo = resolved
		} else {
			let clientName = EncodedString(clientNameInput!)
			_ = try deps.wgdb.clientAssignDomain(domain: targetDomain, name: clientName)
			guard let resolved = try deps.wgdb.allClients().first(where: { $0.name == clientName }) else {
				throw MCPToolError.notFound("client \(String(clientName))")
			}
			clientInfo = resolved
		}
		try await WireguardExecutor.updateExistingClient(publicKey: clientInfo.publicKey, with: Array(clientInfo.domains.values), interfaceName: interfaceName)
		try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		try DNSmasqExecutor.exportAutomaticDNSEntries(db: deps.wgdb)
		try await DNSmasqExecutor.reload()

		let addresses = clientInfo.domains.values.map { $0.string }.joined(separator: ", ")
		return .text("client \(String(clientInfo.name)) added to \(String(targetDomain))\nAddress = \(addresses)")
	}
}

/// MCP tool: remove a client from a domain. Mirrors `wiremand client remove-domain`.
struct ClientRemoveDomainTool: MCPTool {
	static let configuration = MCPToolConfiguration(
		description: "Remove a client from a domain. If it is the client's only domain, the client is revoked and uninstalled from the server.",
		name: "client_remove_domain",
		requiredAccess: .admin
	)
	static func discoverParameters() -> [MCPParameterInfo] {
		[
			MCPParameterInfo(name: "domain", description: "The domain name", required: true, kind: .argument, typeName: "String", hasDefault: false),
			MCPParameterInfo(name: "name", description: "The client name (required unless public_key is provided)", required: false, kind: .option, typeName: "String", hasDefault: true),
			MCPParameterInfo(name: "public_key", description: "The client's base64 wireguard public key (required unless name is provided)", required: false, kind: .option, typeName: "String", hasDefault: true),
		]
	}
	let deps: MCPDeps?
	init() { deps = nil }
	init(deps: MCPDeps) { self.deps = deps }

	func invoke(context: MCPContext) async throws -> MCPToolResult {
		guard let deps else { throw MCPToolError.accessDenied }
		_ = try resolveCallerPublicKey(context: context, wgdb: deps.wgdb)

		let targetDomain = EncodedString(try MCPArgs.requiredString("domain", from: context).lowercased())
		let clientNameInput = MCPArgs.optionalString("name", from: context)
		let publicKeyInput = MCPArgs.optionalString("public_key", from: context)
		guard publicKeyInput != nil || clientNameInput != nil else {
			return .error("provide either 'name' or 'public_key'")
		}
		let (_, _, _, interfaceName, _, _) = try deps.wgdb.getWireguardConfigMetas()

		let removedKey: PublicKey
		let removedName: EncodedString
		let wasFullyRemoved: Bool
		if let publicKeyInput {
			guard let clientKey = PublicKey(argument: publicKeyInput) else {
				return .error("public_key is not a valid wireguard public key")
			}
			guard let preInfo = try deps.wgdb.allClients().first(where: { $0.publicKey == clientKey }) else {
				throw MCPToolError.notFound("client \(clientKey.string)")
			}
			removedName = preInfo.name
			let result = try deps.wgdb.clientRemoveDomain(domain: targetDomain, publicKey: clientKey)
			removedKey = result.0
			wasFullyRemoved = result.1
		} else {
			let clientName = EncodedString(clientNameInput!)
			let result = try deps.wgdb.clientRemoveDomain(domain: targetDomain, name: clientName)
			removedKey = result.0
			wasFullyRemoved = result.1
			removedName = clientName
		}

		if wasFullyRemoved {
			try await WireguardExecutor.uninstall(publicKey: removedKey, interfaceName: interfaceName)
			try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		} else {
			guard let clientInfo = try deps.wgdb.allClients().first(where: { $0.publicKey == removedKey }) else {
				throw MCPToolError.notFound("client \(String(removedName))")
			}
			try await WireguardExecutor.updateExistingClient(publicKey: clientInfo.publicKey, with: Array(clientInfo.domains.values), interfaceName: interfaceName)
			try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: deps.logLevel)
		}
		try DNSmasqExecutor.exportAutomaticDNSEntries(db: deps.wgdb)
		try await DNSmasqExecutor.reload()

		if wasFullyRemoved {
			return .text("client \(String(removedName)) had no remaining domains and was revoked: \(removedKey.string)")
		}
		return .text("client \(String(removedName)) removed from domain \(String(targetDomain))")
	}
}
