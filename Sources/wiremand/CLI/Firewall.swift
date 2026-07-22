import ArgumentParser
import wiremand_databases
import bedrock
import bedrock_ip
import Logging

extension CLI {
	struct Firewall:AsyncParsableCommand {
		enum Error:Swift.Error {
			case missingDomainIdentifier
			case domainNotFound
			case domainTypeMismatch
		}

		static let configuration = CommandConfiguration(
			abstract:"manage the server firewall configuration.",
			subcommands:[AddRule.self, DeleteRules.self, List.self]
		)
		
		struct AddRule:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"adds a firewall rule for a domain. input should be in the form `[match] [match]... [statement] [statement]... verdict` where the verdict should not be drop.",
			)

			@OptionGroup
			var globals:GlobalCLIOptions

			@Option
			var network:wiremand_databases.Network?

			@Option
			var name:EncodedString?

			mutating func run() async throws {
				guard network != nil || name != nil else {
					throw Firewall.Error.missingDomainIdentifier
				}
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let allDomains = try wgdb.allDomains()
				var domainNet:wiremand_databases.Network!
				if let network = network {
					guard allDomains.contains(where:{ $0.network.cidrstring == network.cidrstring }) else {
						throw Firewall.Error.domainNotFound
					}
					domainNet = network
				} else if let name = name {
					guard let domain = allDomains.filter({ $0.name == name }).first else {
						throw Firewall.Error.domainNotFound
					}
					domainNet = domain.network
				}
				let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)

				var ipString = "ip6"
				if domainNet.isV4 { ipString = "ip" }
				var rule:EncodedString? = nil
				while true {
					print(" -> [PROMPT](required) NFTable Firewall rule (\(ipString)): ", terminator:"")
					guard let userInput = readLine(), !userInput.isEmpty else { continue }
					let rules = ["add table \(ipString) testTable", "add chain \(ipString) testTable testChain", "add rule \(ipString) testTable testChain \(ipString) saddr \(domainNet.cidrstring) \(userInput)", "delete table \(ipString) testTable"]
					do {
						let nftableExecutor = try NFTables()
						try nftableExecutor.run(commands: rules)
						rule = EncodedString(userInput)
						break
					} catch {
						print("Invalid rule syntax. Try again.")
					}
				}

				if domainNet.isV4 {
					try firewallDB.addDomainV4Rule(domain:NetworkV4(domainNet.cidrstring)!, rule:rule!)
				} else {
					try firewallDB.addDomainV6Rule(domain:NetworkV6(domainNet.cidrstring)!, rule:rule!)
				}
				
				try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
			}
		}
		
		struct DeleteRules:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"deletes all firewall rules for a given domain.",
			)

			@OptionGroup
			var globals:GlobalCLIOptions

			@Option
			var network:wiremand_databases.Network?

			@Option
			var name:EncodedString?

			mutating func run() async throws {
				guard network != nil || name != nil else {
					throw Firewall.Error.missingDomainIdentifier
				}
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let allDomains = try wgdb.allDomains()
				var domainNet:wiremand_databases.Network!
				if let network = network {
					guard allDomains.contains(where:{ $0.network.cidrstring == network.cidrstring }) else {
						throw Firewall.Error.domainNotFound
					}
					domainNet = network
				} else if let name = name {
					guard let domain = allDomains.filter({ $0.name == name }).first else {
						throw Firewall.Error.domainNotFound
					}
					domainNet = domain.network
				}
				let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				try firewallDB.deleteDomainRules(domain: bedrock_ip.Network(domainNet.cidrstring)!)
				try FirewallExecutor.reloadWhitelist(firewallDB: firewallDB)
			}
		}

		struct List:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the active domain firewall rules.",
			)

			@OptionGroup
			var globals:GlobalCLIOptions

			@Option(name:.shortAndLong)
			var name:EncodedString?

			mutating func run() async throws {
				let firewallDB = try FirewallDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let ipv4Rules = try firewallDB.getIPv4Rules()
				let ipv6Rules = try firewallDB.getIPv6Rules()
				let ipv4Whitelist = Dictionary(uniqueKeysWithValues: ipv4Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
				let ipv6Whitelist = Dictionary(uniqueKeysWithValues: ipv6Rules.map { ($0.key.cidrstring, $0.value.map { String($0) }) })
				var allRules = ipv4Whitelist.merging(ipv6Whitelist) { _, newValue in newValue}

				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let allDomains = try wgdb.allDomains()
				if let name = name {
					guard let domain = allDomains.filter({ $0.name == name }).first else {
						throw Firewall.Error.domainNotFound
					}
					allRules = Dictionary(uniqueKeysWithValues: allRules.filter { $0.key == domain.network.cidrstring })
				}
				
				for (network, rules) in allRules {
					guard let domain = allDomains.filter({ $0.network.cidrstring == network }).first else {
						fatalError()
					}
					print("\(String(domain.name))")
					for rule in rules {
						print(Colors.dim("\t- \(rule)"))
					}
				}
			}
		}
	}
}
