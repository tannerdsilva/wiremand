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
	struct Run:AsyncParsableCommand {
		enum Error:Swift.Error {
			case invalidUser
		}

		static let configuration = CommandConfiguration(
			abstract:"run the daemon process",
			shouldDisplay:false
		)
		
		@Option
		var publicHTTPPort:UInt16 = 8080
		
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
			
			let (_, _, ipv6Addresses, ipv4Address, _, interfaceName, publicIPv4Interface) = try wgdb.getWireguardConfigMetas()
			let v6Addresses = ipv6Addresses.map({ $0.addressString })

			let domains = try wgdb.allDomains()
			let domainIPStrings = domains.map { $0.networks.map { $0.addressString } }.flatMap { $0 }
			let nftableExecutor = try NFTables()
			// let commands = Firewall.createDomainFirewall(domains: try wgdb.allDomains(), interfaceName: String(try wgdb.primaryInterfaceName()), wgListenPort: try wgdb.getPublicListenPort().RAW_native())
			let ipv4Dict = try firewallDB.getAllWhitelistedIPv4()
			let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Dict.map { ($0.key.string, $0.value.map { $0.string }) })
			let ipv6Dict = try firewallDB.getAllWhitelistedIPv6()
			let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Dict.map { ($0.key.string, $0.value.map { $0.string }) })
			let whitelistCommands = FirewallExecutor.createWhitelist(ipv4Dictionary: ipv4Whitelist, ipv6Dictionary: ipv6Whitelist)
			try nftableExecutor.run(commands: whitelistCommands)

			let handshakeChecker = try HandshakeChecker(wgdb: wgdb, ipdb: ipdb, interfaceName: interfaceName, logLevel: globals.logLevel)
			let ipStacker = try IPStacker(ipdb: ipdb, logLevel: globals.logLevel)
			let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
			
			let webserver = try PublicHTTPWebServer(eventLoop: .shared(eventLoopGroup), wgdb: wgdb, hostIPv6: [], hostIPv4: ipv4Address.string, port: UInt16(publicHTTPPort))
			try await ServiceGroup(services:[webserver, handshakeChecker, ipStacker], gracefulShutdownSignals:[.sigterm, .sigint], logger:Logger(label:"wiremand")).run()
		}
	}
}
