import ArgumentParser
import wiremand_databases
import QuickLMDB
import Logging
import Foundation
import SwiftSlash
import bedrock
import Crtnetlink
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

			// Ensure the working directory is accessible by the wiremand user.
			// When launched via systemd the CWD is / (world-readable). When run
			// manually with sudo -u wiremand the CWD is inherited from the caller
			// and may be a root-only directory (e.g. /root), which causes
			// SwiftSlash's precheckDirectory to fail on every child-process spawn.
			guard FileManager.default.changeCurrentDirectoryPath("/") else {
				appLogger.critical("unable to change working directory to /")
				throw Error.invalidUser
			}

			// Raise CAP_NET_ADMIN into the ambient set so that child
			// processes (wg, ip, nft) inherit it. Systemd's
			// AmbientCapabilities= should do this, but on some
			// configurations it does not take effect.
			let capResult = raise_ambient_cap_net_admin()
			if capResult != 0 {
				appLogger.warning("unable to raise ambient CAP_NET_ADMIN (errno \(capResult)); child processes may lack netlink privileges")
			}

			let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)

			let (_, _, _, interfaceName, publicIPv4Interface, publicIPv6Interface) = try wgdb.getWireguardConfigMetas()

			// The firewall is rendered and torn down by a first-class Service so
			// that the ruleset is installed at startup and removed on graceful
			// shutdown. It is declared FIRST in the group so that the ServiceGroup
			// tears it down LAST (services shut down in reverse declaration order),
			// after the other services have stopped serving traffic.
			let firewallService = FirewallService(wgdb: wgdb, firewallDB: firewallDB, firewallPath: firewallPath, logLevel: globals.logLevel)

			// Creating services - Firewall, Handshake Checker, IPStack Resolver, and the Web Server
			let handshakeChecker = try HandshakeChecker(wgdb: wgdb, ipdb: ipdb, interfaceName: interfaceName, logLevel: globals.logLevel)
			let ipStacker = try IPStacker(ipdb: ipdb, logLevel: globals.logLevel)
			let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
			let webserver = try PublicHTTPWebServer(eventLoop: .shared(eventLoopGroup), wgdb: wgdb, hostIPv6: publicIPv6Interface.string, hostIPv4: publicIPv4Interface.string, port: UInt16(publicHTTPPort))

			try await ServiceGroup(services:[firewallService, webserver, handshakeChecker, ipStacker], gracefulShutdownSignals:[.sigterm, .sigint], logger:Logger(label:"wiremand")).run()
		}
	}
}
