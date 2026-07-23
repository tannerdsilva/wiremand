import ArgumentParser
import Foundation
import Logging
import bedrock
import wiremand_databases

extension CLI {
	struct Client:AsyncParsableCommand {
		enum Error:Swift.Error {
			case notFound
			case clientAlreadyExists
		}
		static let configuration = CommandConfiguration(
			abstract:"manage wireguard clients.",
			subcommands:[Punt.self, AddDomain.self, RemoveDomain.self, Revoke.self, Make.self, List.self, Rename.self]
		)
				
		struct Punt:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"'punt' a client's auto-revoke date into the future."
			)

			@OptionGroup
			var domainName:DomainNameGroup

			var globals:GlobalCLIOptions = GlobalCLIOptions()
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				try domainName.promptInteractivelyIfNecessary(db:wgdb)
				
				let newInvalidDate = try wgdb.puntClientInvalidation(domain:domainName.domain!, name:domainName.name!)
				print(Colors.Green("Client punted to \(newInvalidDate.iso8601String())"))
			}
		}
		
		struct AddDomain:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName:"add-domain",
				abstract:"add a client to another domain"
			)

			@OptionGroup
			var domainName:DomainNameGroup
		
			@OptionGroup
			var globals:GlobalCLIOptions

			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				let (_, wgPrimarySubnet, _, interfaceName, _, _) = try wgdb.getWireguardConfigMetas()
				try wgdb.clientAssignDomain(domain:domainName.domain!, name:domainName.name!)
				let clientInfo = try wgdb.allClients().filter { $0.name == domainName.name! }.first!
				try await WireguardExecutor.updateExistingClient(publicKey:clientInfo.publicKey, with:Array(clientInfo.domains.values), interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName, logLevel: globals.logLevel)
				print(Colors.Green("Client successfully added to \(String(domainName.domain!))!"))
				print("Please update the client's WireGuard configuration file!\nIn the [Peer] section of this file, please replace the line containing the \"AllowedIPs\" lines with the following lines:\n")
				let ipEntries = clientInfo.domains.values.map { "\($0.isV4 ? "\($0.string)/24" : "\($0.string)/64")" }
				print("AllowedIPs = \(ipEntries.joined(separator: ", "))")
				let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
				print("AllowedIPs = \(dnsAllowedIPString)")
				
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}

		struct RemoveDomain:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName:"remove-domain",
				abstract:"removes a client from a domain. If it was the clients only domain, then it revokes them and prevents them from connecting to the server."
			)

			@OptionGroup
			var domainName:DomainNameGroup

			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				let (_, wgPrimarySubnet, _, interfaceName, _, _) = try wgdb.getWireguardConfigMetas()
				try domainName.promptInteractivelyIfNecessary(db:wgdb)

				let (removedClientPub, status) = try wgdb.clientRemoveDomain(domain:domainName.domain!, name:domainName.name!)

				if status == true {
					print(Colors.Red("No more domains on the client. Client revoked and uninstalled from the server."))
					try await WireguardExecutor.uninstall(publicKey: removedClientPub, interfaceName: interfaceName)
					try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: globals.logLevel)
				} else {
					let clientInfo = try wgdb.allClients().filter { $0.name == domainName.name! }.first!
					try await WireguardExecutor.updateExistingClient(publicKey:clientInfo.publicKey, with:Array(clientInfo.domains.values), interfaceName:interfaceName)
					try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName, logLevel: globals.logLevel)
					print(Colors.Green("Client successfully removed from \(String(domainName.domain!))!"))
					print("Please update the client's WireGuard configuration file!\nIn the [Peer] section of this file, please replace the line containing the \"AllowedIPs\" lines with the following lines:\n")
					let ipEntries = clientInfo.domains.values.map { "\($0.isV4 ? "\($0.string)/24" : "\($0.string)/64")" }
					print("AllowedIPs = \(ipEntries.joined(separator: ", "))")
					let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
					print("AllowedIPs = \(dnsAllowedIPString)")
				}

				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}
		
		struct Revoke:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"revoke a client and prevent them from connecting to this server."
			)

			@OptionGroup
			var domainName:DomainNameGroup

			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				let interfaceName = try wgdb.primaryInterfaceName()
				try domainName.promptInteractivelyIfNecessary(db:wgdb)

				let removedClientPub = try wgdb.clientRemove(domain:domainName.domain!, name:domainName.name!)
				try await WireguardExecutor.uninstall(publicKey: removedClientPub, interfaceName: interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName, logLevel: globals.logLevel)

				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}
		
		struct Make:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"create a new client that is autorized to connect to this server."
			)
			
			@OptionGroup
			var domainName:DomainNameGroup
						
			@Option(
				name:.shortAndLong,
				help:ArgumentHelp(
					"The pulbic key to use for the newly created client.",
					discussion:"This option is useful for existing WireGuard identities that do not want a new public key."
				)
			)
			var publicKey:PublicKey? = nil
			
			@Flag(
				name:.long,
				help:ArgumentHelp("Do not include DNS instructions in the configuration that is generated for this client.")
			)
			var noDNSService:Bool = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				try domainName.promptInteractivelyIfNecessary(db:wgdb)
				guard try wgdb.validateNewClientName(domain:domainName.domain!, clientName:domainName.name!) == true else {
					fatalError("the client name '\(String(domainName.name!))' cannot be used")
				}
				
				let newKeys = try await WireguardExecutor.generateClient()
				
				var usePublicKey:PublicKey
				if (publicKey == nil) {
					usePublicKey = newKeys.publicKey
				} else {
					usePublicKey = publicKey!
				}
				
				let address = try wgdb.clientMake(name:domainName.name!, publicKey:usePublicKey, domain:domainName.domain!)
				
				let (wgPort, wgPrimarySubnet, pubKey, interfaceName, ipv4Public, ipv6Public) = try wgdb.getWireguardConfigMetas()

				var buildKey = "[Interface]\n"
				if publicKey == nil {
					buildKey += "PrivateKey = " + newKeys.privateKey + "\n"
				}
				let ipAddress = address.string + "\(address.isV4 ? "/32" : "/128")"
				buildKey += "Address = " + ipAddress + "\n"
				buildKey += "DNS = \(wgPrimarySubnet.addressString)\n"
				buildKey += "[Peer]\n"
				buildKey += "PublicKey = \(pubKey.string)\n"
				buildKey += "PresharedKey = \(newKeys.presharedKey)\n"
				let ipAddressSubnet = address.string + "\(address.isV4 ? "/24" : "/64")"
				buildKey += "AllowedIPs = \(ipAddressSubnet)\n"
				let dnsAllowedIPString = "\(wgPrimarySubnet.addressString)\(wgPrimarySubnet.isV4 ? "/32" : "/128")\n"
				buildKey += "AllowedIPs = \(dnsAllowedIPString)"
				buildKey += "Endpoint = \(ipv4Public.string):\(wgPort.RAW_native())\n"
				buildKey += "PersistentKeepalive = 25" + "\n"
				
				try await WireguardExecutor.install(publicKey:usePublicKey, presharedKey:newKeys.presharedKey, addresses:[address], interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName, logLevel: globals.logLevel)
				try wgdb.serveConfiguration(EncodedString(buildKey), forPublicKey:usePublicKey)
				let domainHash = try DomainHash(domainName: domainName.domain!)
				let buildURLV4 = "\nhttps://\(ipv4Public.string):8080/wg_getkey?domain=\(String(domainName.domain!).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)&dk=\(domainHash.string.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)&pk=\(usePublicKey.string.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
				print("\(buildURLV4)")
				let buildURLV6 = "\nhttps://[\(ipv6Public.string)]:8080/wg_getkey?domain=\(String(domainName.domain!).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)&dk=\(domainHash.string.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)&pk=\(usePublicKey.string.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
				print("\(buildURLV6)")
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}
		
		struct List:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the clients that are authorized to connect to this server."
			)
			
			@Option(
				name:.shortAndLong,
				help:ArgumentHelp(
					"Filter the list to a specified domain."
				)
			)
			var domain:EncodedString? = nil
			
			@Flag(
				name:.shortAndLong,
				help:ArgumentHelp("Print IPv6 addresses in a Windows-friendly format.")
			)
			var windowsLegacy = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				let ipdb = try IPDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				var allClients = Set<WireguardDatabase.ClientInfo>()
				if (domain != nil) {
					allClients = try wgdb.allClients(domain:domain)
				} else {
					allClients = try wgdb.allClients()
				}

				var domainGroup = [EncodedString:[WireguardDatabase.ClientInfo]]()

				for client in allClients {
					for domain in client.domains.keys {
						domainGroup[domain, default: []].append(client)
					}
				}

				let iterateList = domainGroup.sorted(by: { $0.key < $1.key })
				let nowDate = bedrock.Date.Seconds()
				for domainToList in iterateList {
					// print the domain name
					print(Colors.Yellow("\(String(domainToList.key))"))
					
					// print the sorted clients
					let sortedClients = domainToList.value.sorted(by: { $0.name < $1.name })
					for curClient in sortedClients {
						if (curClient.lastHandshake == nil) {
							// print the name in dim text since the client has never successfully handshaken
							print(Colors.dim("\t- \(String(curClient.name))"), terminator:"\n")
						} else {
							if (curClient.lastHandshake!.timeIntervalSinceNow > -150) {
								// print the name in green text since the client is online
								print(Colors.Green("\t- \(String(curClient.name))"), terminator:"")
								
								// endpoint info
								if let hasEndpoint = curClient.endpoint {
									if case let IPDatabase.ResolveStatus.resolved(resInfo) = try ipdb.getResolveStatus(address:hasEndpoint.description) {
										if let hasCity = resInfo.city, let hasState = resInfo.region?.code {
											print(Colors.dim("\n\t  - Connected from \(String(hasCity)), \(String(hasState)) at \(hasEndpoint)"), terminator:"")
										} else if let hasState = resInfo.region?.name {
											print(Colors.dim("\n\t  - Connected from \(String(hasState)) at \(hasEndpoint)"), terminator:"")
										}
									} else {
										print(Colors.dim("\n\t  - Connected at \(hasEndpoint)"), terminator:"")
									}
								} else {
									print(Colors.dim("\n\t  - Connected at unknown endpoint"), terminator:"")
								}
							} else if curClient.invalidationDate.timeIntervalSinceNow < 43200 {
								// print the name in red text since the client is going to be revoked soon
								print(Colors.Red("\t- \(String(curClient.name))"), terminator:"")
							} else {
								// print the name in white text because the client has successfully made a handshake in the past, but is currently offline
								print("\t- \(String(curClient.name))", terminator:"")
								
								// endpoint info
								print(Colors.dim("\n\t  - \(curClient.lastHandshake!.relativeTimeString(to:nowDate).lowercased()) "), terminator:"")
								if let hasEndpoint = curClient.endpoint {
									if case let IPDatabase.ResolveStatus.resolved(resInfo) = try ipdb.getResolveStatus(address:hasEndpoint.description) {
										if let hasCity = resInfo.city, let hasState = resInfo.region?.code {
											print(Colors.dim("from \(String(hasCity)), \(String(hasState)) at \(hasEndpoint)"), terminator:"")
										} else if let hasState = resInfo.region?.name {
											print(Colors.dim("from \(String(hasState)) at \(hasEndpoint)"), terminator:"")
										}
									} else {
										print(Colors.dim("at \(hasEndpoint)"), terminator:"")
									}
								} else {
									print(Colors.dim("at unknown endpoint"), terminator:"")
								}
							}
							
							print("\n", terminator:"")
							
							// print the client address
							if (windowsLegacy == false) {
								let address = curClient.domains[domainToList.key]!.string
								print(Colors.dim("\t  - \(address)"), terminator:"")
							} else {
								let replaceString = curClient.domains[domainToList.key]!.string.replacingOccurrences(of: ":", with: "-") + ".ipv6-literal.net"
								print(Colors.cyan("\t  - \(replaceString)"), terminator:"")
							}
							
							// print the public key of the client
							print(Colors.dim("\n\t  - Public key: \(curClient.publicKey.string)"))
						} 
					}
				}
			}
		}
		
		struct Rename:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"modify the name of an existing client within its domain."
			)
			
			@Argument(help:ArgumentHelp(
				"The public key of the client that is to be renamed."
			))
			var publicKey:PublicKey
			
			@Argument(help:ArgumentHelp(
				"The new name to assign to the client."
			))
			var newName:EncodedString
			
			@OptionGroup
			var globals:GlobalCLIOptions
						
			mutating func run() async throws {
				let wgdb = try WireguardDatabase(base: Path(globals.databasePath), logLevel: globals.logLevel)
				
				try wgdb.clientRename(publicKey:publicKey, name:newName)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:wgdb)
				try await DNSmasqExecutor.reload()
			}
		}
	}
}

extension CLI.Client {
	struct DomainNameGroup:ParsableArguments {
		@Option(
			name:.shortAndLong,
			help:ArgumentHelp(
				"The relevant domain name."
			)
		)
		var domain:EncodedString? = nil
		
		@Option(
			name:.shortAndLong,
			help:ArgumentHelp(
				"The name of the client."
			)
		)
		var name:EncodedString? = nil
		
		mutating func promptInteractivelyIfNecessary(db wgdb:WireguardDatabase, noClientsAllowed:Bool = false) throws {
			// determine the domain to use
			if (domain == nil || String(domain!).count == 0) {
				let allDomains = try wgdb.allDomains()
				switch allDomains.count {
					case 0:
						print(Colors.Red("There are no domains configured (this should not be the case)"))
					case 1:
						domain = allDomains.first!.name
					default:
						print("Please select a domain for this action:")
						for curSub in allDomains {
							print(Colors.dim("  - \(String(curSub.name))"))
						}
						repeat {
							print("Domain name: ", terminator:"")
							let rl = readLine()
							domain = rl == nil ? nil : EncodedString(rl!)
						} while domain == nil || String(domain!).count == 0
				}
			}
			guard try wgdb.validateDomain(name:domain!) == true else {
				print(Colors.Red("The domain name '\(String(domain!))' does not exist"))
				throw CLI.Client.Error.notFound
			}
			
			// determine the name to use
			if (name == nil || String(name!).count == 0) {
				let allClients = try wgdb.allClients(domain:domain!)
				switch allClients.count {
					case 0:
						print(Colors.Yellow("There are no clients on this domain yet."))
						if (noClientsAllowed == false) {
							throw CLI.Client.Error.notFound
						}
					default:
						print(Colors.Yellow("There are \(allClients.count) clients on this domain:"))
						for curClient in allClients.sorted(by: { $0.name < $1.name }) {
							print(Colors.dim("\t-\t\(String(curClient.name))"))
						}
				}
				repeat {
					print("Client name: ", terminator:"")
					let rl = readLine()
					name = rl == nil ? nil : EncodedString(rl!)
				} while name == nil && String(name!).count == 0
			}
		}
	}
}
