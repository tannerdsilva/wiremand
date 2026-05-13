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

			guard getCurrentUser() == "wiremand" else {
				print("this function must be run as the wiremand user")
				throw Error.invalidUser
			}
			
			let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			
			let (_, _, ipv6Addresses, ipv4Address, _, interfaceName, _) = try wgdb.getWireguardConfigMetas()

			let handshakeChecker = try HandshakeChecker(wgdb: wgdb, ipdb: ipdb, interfaceName: interfaceName, logLevel: globals.logLevel)
			let ipStacker = try IPStacker(ipdb: ipdb, logLevel: globals.logLevel)
			let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
			let webserver = try PublicHTTPWebServer(eventLoop: .shared(eventLoopGroup), wgdb: wgdb, hostIPv6: ipv6Addresses.map({ $0.addressString }), hostIPv4: ipv4Address.string, port: UInt16(publicHTTPPort))
			try await ServiceGroup(services:[webserver, handshakeChecker, ipStacker], gracefulShutdownSignals:[.sigterm, .sigint], logger:Logger(label:"wiremand")).run()
		}
	}
}
