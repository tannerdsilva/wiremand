import MCP
import Foundation
import Logging
import wiremand_databases

/// Errors thrown by the wiremand MCP tools when authorization or argument
/// validation fails. These surface as MCP `tools/call` errors.
enum MCPToolError: Swift.Error, LocalizedError {
	case accessDenied
	case missingArgument(String)
	case invalidArgument(String)
	case notFound(String)
	case operationFailed(String)

	var errorDescription: String? {
		switch self {
			case .accessDenied:
				return "access denied"
			case .missingArgument(let name):
				return "missing required argument: \(name)"
			case .invalidArgument(let message):
				return "invalid argument: \(message)"
			case .notFound(let what):
				return "not found: \(what)"
			case .operationFailed(let message):
				return "operation failed: \(message)"
		}
	}
}

/// Argument extraction helpers for MCP tool invocation.
/// JSON-RPC arguments arrive as `Any`; these helpers coerce the JSON types
/// (String, Bool) that the wiremand tool surface uses.
enum MCPArgs {
	static func requiredString(_ key: String, from context: MCPContext) throws -> String {
		guard let rawValue = context.arguments[key] else {
			throw MCPToolError.missingArgument(key)
		}
		guard let value = rawValue as? String, !value.isEmpty else {
			throw MCPToolError.invalidArgument("\(key) must be a non-empty string")
		}
		return value
	}

	static func optionalString(_ key: String, from context: MCPContext) -> String? {
		guard let rawValue = context.arguments[key] else { return nil }
		return rawValue as? String
	}

	static func boolFlag(_ key: String, from context: MCPContext) -> Bool {
		(context.arguments[key] as? Bool) ?? false
	}
}

/// Shared runtime dependencies for every wiremand MCP tool.
///
/// The daemon constructs one instance of this value and hands it to each
/// tool at registration time; tools cannot reach the database or execute
/// layer any other way.
struct MCPDeps: Sendable {
	let wgdb: WireguardDatabase
	let ipdb: IPDatabase
	let firewallDB: FirewallDatabase
	let interfaceName: EncodedString
	let logLevel: Logger.Level
}

/// Resolves the WireGuard peer identity backing an incoming MCP connection.
///
/// - Parses the IP out of the transport's remote-address string.
/// - Reverse-maps it to a client public key through the `ip_clientPub`
///   database (unforgeable inside the authenticated tunnel: the kernel only
///   routes packets whose source address belongs to that peer).
/// - Requires the client to hold the MCP grant bit.
///
/// Re-run on every tool invocation so that revoking the grant (or removing
/// the client) takes effect immediately on already-open connections.
func resolveCallerPublicKey(context: MCPContext, wgdb: WireguardDatabase) throws -> PublicKey {
	guard let sourceAddress = context.callerInfo?.sourceAddress,
		let ipString = ipString(fromRemoteAddress: sourceAddress),
		let address = Address(ipString) else {
		throw MCPToolError.accessDenied
	}
	let publicKey: PublicKey
	do {
		publicKey = try wgdb.clientPublicKey(forAddress: address)
	} catch {
		throw MCPToolError.accessDenied
	}
	guard (try? wgdb.hasMCPAccess(publicKey: publicKey)) == true else {
		throw MCPToolError.accessDenied
	}
	return publicKey
}

/// Parses the IP portion of a NIO remote-address description.
///
/// NIO's `SocketAddress.description` always carries a scheme prefix:
///   - "[IPv4]10.0.20.5:49152" -> "10.0.20.5"
///   - "[IPv6]fd00::1:49152" -> "fd00::1"
///
/// IPv4-mapped IPv6 (e.g. "[IPv6]::ffff:127.0.0.1:49152") is rejected: the
/// mapped address must never match against a tunnel key. Any string that is
/// not a scheme-prefixed host:port description yields nil (fail closed).
func ipString(fromRemoteAddress remoteAddress: String) -> String? {
	var remainder = remoteAddress
	if remainder.hasPrefix("[IPv4]") {
		remainder.removeFirst("[IPv4]".count)
	} else if remainder.hasPrefix("[IPv6]") {
		remainder.removeFirst("[IPv6]".count)
	} else {
		return nil
	}
	guard let colon = remainder.lastIndex(of: ":") else { return nil }
	let host = String(remainder[..<colon])
	// reject IPv4-mapped IPv6 addresses: the server's reverse lookup keys on
	// real tunnel addresses only, and a mapped address would be ambiguous.
	guard !host.lowercased().contains("::ffff:") else { return nil }
	return host
}
