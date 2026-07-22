import ArgumentParser
import wiremand_databases
import bedrock
import bedrock_ip
import Logging

extension CLI {
	struct Domain:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"manage the domains on wiremand.",
			subcommands:[Make.self, Remove.self, List.self]
		)
		
		struct Make:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"install a domain on this wiremand system."
			)
	
			@Argument
			var domainName:String
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				var appLogger = Logger(label:"wiremand")
				appLogger.logLevel = globals.logLevel

				let interfaceName = try wgdb.primaryInterfaceName()

				var ipScope:wiremand_databases.Network? = nil
				repeat {
					print(" -> [PROMPT](required) subnet block (v4 or v6): ", terminator:"")
					if let asString = readLine(), let asNetwork = wiremand_databases.Network(asString) {
						ipScope = asNetwork
					}
				} while ipScope == nil
				
				let newSK = try wgdb.domainMake(name:EncodedString(domainName.lowercased()), subnet: ipScope!)
				try await WireguardExecutor.installDomain(subnet: ipScope!, interfaceName: interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: globals.logLevel)
				let domainHash = try DomainHash(domainName: EncodedString(domainName))
				appLogger.info("domain created successfully.", metadata:["_sk":"\(newSK.string)", "_dk":"\(domainHash.string)", "domain":"\(ipScope!.cidrstring)"])

				try FirewallExecutor.reloadDomainIsolation(wgdb: wgdb)
			}
		}
		
		struct Remove:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"remove a domain from this system.",
				discussion:"will instantly invalidate all users within the submet."
			)

			@Argument
			var domainName:String
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let interfaceName = try wgdb.primaryInterfaceName()
				let removedClients = try wgdb.allClients(domain: EncodedString(domainName.lowercased()))
				let subnet = try wgdb.domainRemove(name:EncodedString(domainName.lowercased()))
				try await WireguardExecutor.uninstallDomain(subnet: subnet, interfaceName: interfaceName)
				for client in removedClients {
					try await WireguardExecutor.uninstall(publicKey: client.publicKey, interfaceName: interfaceName)
				}
				try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: globals.logLevel)
				try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
				try FirewallExecutor.reloadDomainIsolation(wgdb: wgdb)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}
		
		struct List:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the domains that are available on this system."
			)
			
			@Flag(help:ArgumentHelp("show wiremand API keys for the domains."))
			var apiKeys:Bool = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let allDomains = try wgdb.allDomains()
				for curDomain in allDomains {
					print("\(String(curDomain.name))")
					if (self.apiKeys == true) {
						print(Colors.Yellow("\t- sk: \(curDomain.securityKey.string)"))
						print(Colors.Cyan("\t- dk: \(try DomainHash(domainName: curDomain.name).string)"))
					}
					print(Colors.dim("\t- subnets: \(curDomain.network.cidrstring)"))
				}
			}
		}
	}
}
