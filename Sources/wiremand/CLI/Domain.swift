import ArgumentParser
import wiremand_databases
import bedrock
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
				
				let (newDomain, newSK) = try wgdb.domainMake(name:EncodedString(domainName.lowercased()))
				let domainHash = try DomainHash(domainName: EncodedString(domainName))
				appLogger.info("domain created successfully.", metadata:["_sk":"\(newSK.string)", "_dk":"\(domainHash.string)", "domain":"\(newDomain.cidrstring)"])

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
				let removedClients = try wgdb.allClients(domain: EncodedString(domainName.lowercased()))
				try wgdb.domainRemove(name:EncodedString(domainName.lowercased()))
				for client in removedClients {
					try firewallDB.removeClient(client: client)
				}
				try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
				try FirewallExecutor.reloadDomainIsolation(wgdb: wgdb)
				try FirewallExecutor.removeDomainSet(domain: domainName.lowercased())
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
					print(Colors.dim("\t- subnets: \(curDomain.networks.map(\.cidrstring).joined(separator: ", "))"))
				}
			}
		}
	}
}
