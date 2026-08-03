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
				let (_, wgPrimarySubnet, _, interfaceName, _, _) = try wgdb.getWireguardConfigMetas()
				let removedClients = try wgdb.allClients(domain: EncodedString(domainName.lowercased()))
				let (subnet, clientStatuses) = try wgdb.domainRemove(name:EncodedString(domainName.lowercased()))
				try await WireguardExecutor.uninstallDomain(subnet: subnet, interfaceName: interfaceName)
				let allClients = try wgdb.allClients()
				for client in removedClients {
					if clientStatuses[client.publicKey] == true {
						print(Colors.Red("Client revoked and uninstalled from the server.\n\t - PublicKey: \(client.publicKey.string)\n\t - Name: \(String(client.name))"))
						try await WireguardExecutor.uninstall(publicKey: client.publicKey, interfaceName: interfaceName)
					} else {
						print(Colors.Yellow("Client removed from domain, but still exists in the server."))
						print(Colors.Yellow("\t - PublicKey: \(client.publicKey.string)\n\t - Name: \(String(client.name))"))
						let clientInfo = allClients.filter { $0.publicKey == client.publicKey }.first!
						let remainingDomains = clientInfo.domains.keys.map { String($0) }.joined(separator: ", ")
						print(Colors.Yellow("\t - Domains: \(remainingDomains)"))
						let addresses = clientInfo.domains.values.map { $0.string }.joined(separator: ", ")
						print("\t Change this client key's Address and AllowedIP fields")
						print("\t - Address = \(addresses)")
						let ipEntries = clientInfo.domains.values.map { 
							if $0.isV4 {
								String(bedrock_ip.AddressV4(subnetPrefix: 24)! & bedrock_ip.AddressV4($0.string)!) + "/24"
							} else {
								String(bedrock_ip.AddressV6(subnetPrefix: 64)! & bedrock_ip.AddressV6($0.string)!) + "/64"
							}
						}
						print("\t - AllowedIPs = \(ipEntries.joined(separator: ", "))")
						let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
						print("\t - AllowedIPs = \(dnsAllowedIPString)")
					}
					
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
