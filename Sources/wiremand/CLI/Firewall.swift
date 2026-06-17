import ArgumentParser
import wiremand_databases
import bedrock
import Logging

extension CLI {
	struct Firewall:AsyncParsableCommand {
		enum Error:Swift.Error {
			case missingClientIdentifier
			case noClientIPv4Installed
			case clientNotFound
		}

		static let configuration = CommandConfiguration(
			abstract:"manage the server firewall configuration.",
			subcommands:[Whitelist.self, Blacklist.self]
		)
		
		struct Whitelist:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"whitelist ips for clients.",
				subcommands:[IPv4.self, IPv6.self]
			)

			struct IPv4: AsyncParsableCommand {
				static let configuration = CommandConfiguration (
					commandName: "ipv4",
					abstract:"whitelist ipv4 addresses for a client."
				)

				@Option
				var name:EncodedString?

				@Option 
				var publicKey:PublicKey?

				@OptionGroup
				var globals:GlobalCLIOptions

				@Argument
				var whitelistV4s:[AddressV4]

				mutating func run() async throws {
					guard name != nil || publicKey != nil else {
						throw Firewall.Error.missingClientIdentifier
					}
					let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
					let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
					let allClients = try wgdb.allClients()
					let client:WireguardDatabase.ClientInfo?

					if name != nil {
						client = allClients.first(where: { $0.name == name })
					} else {
						client = allClients.first(where: { $0.publicKey == publicKey })
					}
					guard let client = client else {
						throw Firewall.Error.clientNotFound
					}
					guard let clientAddress = client.addressV4 else {
						throw Firewall.Error.noClientIPv4Installed
					}

					try firewallDB.addWhitelistIPv4(clientIP: clientAddress, whitelist: whitelistV4s)

					let _ = try firewallDB.getAllWhitelistedIPv4()
					try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
				}
			}

			struct IPv6: AsyncParsableCommand {
				static let configuration = CommandConfiguration (
					commandName: "ipv6",
					abstract:"whitelist ipv6 addresses for a client."
				)

				@OptionGroup
				var globals:GlobalCLIOptions

				@Argument
				var clientV6:AddressV6

				@Argument
				var whitelistV6s:[AddressV6]

				mutating func run() async throws {
					let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)

					try firewallDB.addWhitelistIPv6(clientIP: clientV6, whitelist: whitelistV6s)
					try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
				}
			}
		}
		
		struct Blacklist:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"blacklist ips for clients.",
				subcommands:[IPv4.self, IPv6.self]
			)

			struct IPv4: AsyncParsableCommand {
				static let configuration = CommandConfiguration (
					commandName: "ipv4",
					abstract:"removes ipv4 addresses from a client's whitelist."
				)

				@Option
				var name:EncodedString?

				@Option 
				var publicKey:PublicKey?

				@OptionGroup
				var globals:GlobalCLIOptions

				@Argument
				var blacklistV4s:[AddressV4]

				mutating func run() async throws {
					var appLogger = Logger(label:"firewall")
					appLogger.logLevel = globals.logLevel

					guard name != nil || publicKey != nil else {
						throw Firewall.Error.missingClientIdentifier
					}
					let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
					let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
					let allClients = try wgdb.allClients()
					let client:WireguardDatabase.ClientInfo?

					if name != nil {
						client = allClients.first(where: { $0.name == name })
					} else {
						client = allClients.first(where: { $0.publicKey == publicKey })
					}
					guard let client = client else {
						throw Firewall.Error.clientNotFound
					}
					guard let clientAddress = client.addressV4 else {
						throw Firewall.Error.noClientIPv4Installed
					}

					let successfullyRemoved = try firewallDB.removeWhitelistIPv4(clientIP: clientAddress, whitelist: blacklistV4s)
					for ipv4 in successfullyRemoved {
						appLogger.info("successfully removed ip from whitelist", metadata: ["IPv4Address":"\(ipv4.string)"])
					}
					if !successfullyRemoved.isEmpty { try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB) }
				}
			}

			struct IPv6: AsyncParsableCommand {
				static let configuration = CommandConfiguration (
					commandName: "ipv6",
					abstract:"removes ipv6 addresses from a client's whitelist."
				)

				@OptionGroup
				var globals:GlobalCLIOptions

				@Argument
				var clientV6:AddressV6

				@Argument
				var whitelistV6s:[AddressV6]

				mutating func run() async throws {
					var appLogger = Logger(label:"firewall")
					appLogger.logLevel = globals.logLevel
					
					let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)

					let successfullyRemoved = try firewallDB.removeWhitelistIPv6(clientIP: clientV6, whitelist: whitelistV6s)
					for ipv6 in successfullyRemoved {
						appLogger.info("successfully removed ip from whitelist", metadata: ["IPv6Address":"\(ipv6.string)"])
					}
					if !successfullyRemoved.isEmpty { try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB) }
				}
			}
		}
	}
}
