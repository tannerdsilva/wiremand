import MCP
import Logging
import NIO
import wiremand_databases

/// Builds and registers the wiremand MCP admin server.
///
/// Security model:
/// - The server binds to the server's own wireguard interface address only;
///   reachability requires passing through the authenticated tunnel.
/// - At accept time, the transport's access resolver reverse-maps the peer's
///   source address to a client public key through `ip_clientPub` and
///   requires the MCP grant bit. Anything else resolves to `.public`, which
///   is below every tool's `requiredAccess` threshold.
/// - At call time, every tool re-resolves the caller identity and re-checks
///   the grant bit, so revoking access takes effect immediately on
///   already-open connections.
enum MCPAccessServer {
	static func makeServer(
		address: ServerAddress,
		deps: MCPDeps,
		eventLoopGroup: EventLoopGroup
	) -> MCPServer {
		let wgdb = deps.wgdb
		let transport = TCPTransport(
			address: address,
			eventLoopGroup: eventLoopGroup,
			accessResolver: { remoteAddress in
				guard let ipPart = ipString(fromRemoteAddress: remoteAddress),
					let address = Address(ipPart),
					let publicKey = try? wgdb.clientPublicKey(forAddress: address),
					(try? wgdb.hasMCPAccess(publicKey: publicKey)) == true
				else {
					return .public
				}
				return .admin
			}
		)
		let server = MCPServer(name: "wiremand", version: "1.0.0", transport: transport)
		server.logLevel = deps.logLevel

		let tools: [any MCPTool] = [
			DomainMakeTool(deps: deps), DomainListTool(deps: deps),
			ClientMakeTool(deps: deps), ClientListTool(deps: deps), ClientRenameTool(deps: deps),
			ClientRevokeTool(deps: deps), ClientPuntTool(deps: deps),
			ClientAddDomainTool(deps: deps), ClientRemoveDomainTool(deps: deps),
			FirewallAddRuleTool(deps: deps), FirewallDeleteRulesTool(deps: deps), FirewallListTool(deps: deps),
			IPStackSetAPIKeyTool(deps: deps), IPStackGetAPIKeyTool(deps: deps),
			ResetPublicAddressesTool(deps: deps),
		]
		for tool in tools {
			server.registerInstance(type(of: tool).toolName, instance: tool)
		}
		return server
	}
}
