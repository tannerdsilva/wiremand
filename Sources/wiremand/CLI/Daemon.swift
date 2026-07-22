import ArgumentParser
import wiremand_databases
import QuickLMDB
import Logging
import Foundation
import SwiftSlash
import bedrock
import ServiceLifecycle
import NIO
//import SignalStack

extension CLI {
	/// Builds the firewall for any network traffic using NFTables on Linux.
	/// Firewall contains the following features:
	/// - Custom User Commands: The custom NFTable commands added via the text file found at firewallPath.
	/// - Client Whitelist: A whitelist that blocks all incoming traffic per client except for the addresses specified through the Firewall CLI.
	///
	/// Runs the services necessary for wiremand to function.
	/// Services:
	/// - HandshakeChecker: Checks the servers peers for any changes in handshakes. See HandshakeChecker for more details.
	/// - IPStacker: Keeps ip information up to date. See IPStacker for more details..
	/// - WebServer: The hosted server for catching incoming HTTP requests. See PublicHTTPWebServer for more details.
	struct Run:AsyncParsableCommand {
		enum Error:Swift.Error {
			case invalidUser
			case missingFirewallFile
		}

		static let configuration = CommandConfiguration(
			abstract:"run the daemon process",
			shouldDisplay:false
		)
		
		@Option
		var publicHTTPPort:UInt16 = 8080

		@Option
		var firewallPath:String = "/var/lib/wiremand/firewallCommands.txt"
		
		@OptionGroup
		var globals:GlobalCLIOptions
		
		mutating func run() async throws {
			umask(000)
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = globals.logLevel

			// guard getCurrentUser() == "wiremand" else {
			// 	print("this function must be run as the wiremand user")
			// 	throw Error.invalidUser
			// }

			let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			
			let (_, _, _, interfaceName, publicIPv4Interface, publicIPv6Interface) = try wgdb.getWireguardConfigMetas()

			// Setting up the firewall
			let fileContent:String!
			do {
				fileContent = try String(contentsOfFile: firewallPath, encoding: .utf8)
				appLogger.warning("Reading \(firewallPath) for the custom firewall rules.")
			} catch {
				appLogger.warning("Missing firewall file. Add the \(firewallPath) file and run again.")
				throw Self.Error.missingFirewallFile
			}
			let bootFirewallCommands = fileContent.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
			let domainIsolationCommands = FirewallExecutor.createDomainFirewall(domains: try wgdb.allDomains(), interfaceName: String(try wgdb.primaryInterfaceName()), wgListenPort: try wgdb.getPublicListenPort().RAW_native())
			let ipv4Rules = try firewallDB.getIPv4Rules()
			let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
			let ipv6Rules = try firewallDB.getIPv6Rules()
			let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
			let whitelistCommands = FirewallExecutor.createWhitelist(ipv4Rules:ipv4Whitelist, ipv6Rules:ipv6Whitelist)
			let ipFilters = FirewallExecutor.createIPFilters()
			let nftableExecutor = try NFTables()
			try nftableExecutor.run(commands: bootFirewallCommands + ipFilters + whitelistCommands + domainIsolationCommands)

			// Creating services - Handshake Checker, IPStack Resolver, and the Web Server
			let handshakeChecker = try HandshakeChecker(wgdb: wgdb, ipdb: ipdb, interfaceName: interfaceName, logLevel: globals.logLevel)
			let ipStacker = try IPStacker(ipdb: ipdb, logLevel: globals.logLevel)
			let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
			let webserver = try PublicHTTPWebServer(eventLoop: .shared(eventLoopGroup), wgdb: wgdb, hostIPv6: publicIPv6Interface.string, hostIPv4: publicIPv4Interface.string, port: UInt16(publicHTTPPort))

			try await ServiceGroup(services:[webserver, handshakeChecker, ipStacker], gracefulShutdownSignals:[.sigterm, .sigint], logger:Logger(label:"wiremand")).run()
		}
	}
}
