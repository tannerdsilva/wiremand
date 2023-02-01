import ArgumentParser
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
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			@Argument
			var domainName:String
			
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				var appLogger = Logger(label:"wiremand")
				appLogger.logLevel = globals.logLevel
				try await CertbotExecute.acquireSSL(domain: domainName.lowercased(), daemon:daemonDB)
				try NginxExecutor.install(domain: domainName.lowercased())
				try await NginxExecutor.reload()
				let (newSubnet, newSK) = try daemonDB.wireguardDatabase.subnetMake(name:domainName.lowercased())
				let domainHash = try WiremanD.hash(domain:domainName)
				appLogger.info("domain created successfully.", metadata:["_sk":"\(newSK)", "_dk":"\(domainHash)", "subnet":"\(newSubnet.cidrString)"])
			}
		}
		
		struct Remove:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"remove a domain from this system.",
				discussion:"will instantly invalidate all users within the submet."
			)

			@OptionGroup
			var globals:GlobalCLIOptions
			
			@Argument
			var domainName:String
			
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.wireguardDatabase.subnetRemove(name:domainName.lowercased())
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
				try await DNSmasqExecutor.reload()
				try NginxExecutor.uninstall(domain:domainName.lowercased())
				try await NginxExecutor.reload()
				try await CertbotExecute.removeSSL(domain:domainName)
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
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				let allDomains = try daemonDB.wireguardDatabase.allSubnets()
				for curDomain in allDomains {
					print("\(curDomain.name)")
					if (self.apiKeys == true) {
						print(Colors.Yellow("\t- sk: \(curDomain.securityKey)"))
						print(Colors.Cyan("\t- dk: \(try WiremanD.hash(domain:curDomain.name))"))
					}
					print(Colors.dim("\t- subnet: \(curDomain.network.cidrString)"))
				}
			}
		}
	}
}