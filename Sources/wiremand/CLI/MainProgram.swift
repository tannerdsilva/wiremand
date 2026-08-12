import ArgumentParser
import bedrock
import wiremand_databases
import Logging

@main
struct CLI:AsyncParsableCommand {
	struct GlobalCLIOptions:ParsableArguments {
#if DEBUG
//		@Option
		var logLevel:Logging.Logger.Level = .debug
#else
//		@Option(help:ArgumentHelp(visibility:.`private`))
		var logLevel:Logging.Logger.Level = .info
#endif
		
		var databasePath:String = "/var/lib/wiremand"
	}
	
	
	public static let configuration = CommandConfiguration(
		commandName: "wiremand",
		abstract: "A command-line tool for managing WireGuard configurations.",
		subcommands: [
			Installer.self,
			Updater.self,
			ResetPublicAddresses.self,
			Domain.self,
			Client.self,
			Run.self,
			Firewall.self,
			IPStack.self,
		]
	)

	public struct ResetPublicAddresses:ParsableCommand {
		public static let configuration = CommandConfiguration(
			commandName: "reset-public-addresses",
			abstract: "Resets the public ipv4 and ipv6 addresses for emergency scenarios where the ips somehow changed after installation."
		)

		@OptionGroup
		var globals:GlobalCLIOptions

		public mutating func run() throws {
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = globals.logLevel

			let routesV4 = try RTNetlink.getRoutesV4()
    		let filteredRoutesV4 = routesV4.filter { $0.destination_length == 0 }
			guard !filteredRoutesV4.isEmpty else {
				appLogger.error("there is no default IPv4 route")
				throw Installer.Error.ipv4DefaultRouteUnknown
			}

			let addressV4 = try RTNetlink.getAddressesV4()
      		let filteredV4 = addressV4.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 } 

			guard let defaultV4Address = filteredV4.first!.address else {
				appLogger.error("no defaultV4 source address")
				throw Installer.Error.ipv4DefaultRouteUnknown
			}

			let resExtV4 = AddressV4(defaultV4Address)

			let addressV6 = try RTNetlink.getAddressesV6()
      		let filteredV6 = addressV6.filter { $0.interfaceName == filteredRoutesV4.first!.outputInterfaceName && $0.scope == 0 && !$0.flags.isTemporary }

			let resExtV6:AddressV6?

			if filteredV6.isEmpty {
				appLogger.warning("there is no valid default IPv6 route, will bind to [::] instead")
				resExtV6 = AddressV6("::")
			} else {
				resExtV6 = AddressV6(filteredV6.first!.address!)
			}

			let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
			try wgdb.installPublicIPAddresses(wg_resolvedServerPublicIPv4:resExtV4!, wg_resolvedServerPublicIPv6:resExtV6!)
			appLogger.info("Successfully changed the public ip addresses. \n\t - PublicIPv4: \(resExtV4!.string)\n\t - PublicIPv6: \(resExtV6!.string)")
		}
	}
}

extension Path:@retroactive ExpressibleByArgument {
	public init?(argument:String) {
		self.init(argument)
	}
}
