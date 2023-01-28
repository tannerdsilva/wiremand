import ArgumentParser
import SwiftBlake2
import Foundation

extension CLI {
	struct Client:AsyncParsableCommand {
		enum Error:Swift.Error {
			case notFound
		}
		static let configuration = CommandConfiguration(
			abstract:"manage wireguard clients.",
			subcommands:[Punt.self, ProvisionIPv4.self, Revoke.self, Make.self, List.self, Rename.self]
		)
				
		struct Punt:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"'punt' a client's auto-revoke date into the future."
			)

			@OptionGroup
			var domainName:DomainNameGroup

			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				
				try domainName.promptInteractivelyIfNecessary(db:daemonDB)
				
				let newInvalidDate = try daemonDB.wireguardDatabase.puntClientInvalidation(subnet:domainName.domain!, name:domainName.name!)
				let df = ISO8601DateFormatter()
				print(Colors.Green("Client punted to \(df.string(from:newInvalidDate))"))
			}
		}
		
		struct ProvisionIPv4:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName:"provision-ipv4",
				abstract:"assign an IPv4 address to a client."
			)

			@OptionGroup
			var domainName:DomainNameGroup
		
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				
				try domainName.promptInteractivelyIfNecessary(db:daemonDB)

				let (_, _, _, _, _, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()
				let (newV4, curV6, pubString) = try daemonDB.wireguardDatabase.clientAssignIPv4(subnet:domainName.domain!, name:domainName.name!)
				try await WireguardExecutor.updateExistingClient(publicKey:pubString, with:curV6, and:newV4, interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
				print(Colors.Green("Client IPv4 address successfully applied!"))
				print("Please update the client's WireGuard configuration file!\nIn the [Peer] section of this file, please replace the line containing the \"AllowedIPs\" with the following line:\n")
				print("AllowedIPs=\(curV6.string)/128,\(newV4.string)/32")
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
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				
				try domainName.promptInteractivelyIfNecessary(db:daemonDB)

				try daemonDB.wireguardDatabase.clientRemove(subnet:domainName.domain!, name:domainName.name!)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
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
			var publicKey:String? = nil
			
			@Flag(
				name:.long,
				help:ArgumentHelp("Do not include DNS instructions in the configuration that is generated for this client.")
			)
			var noDNS:Bool = false
			
			@Flag(name:[
					.customShort("4", allowingJoined:true),
					.customLong("ipv4", withSingleDash:false)
				], 
				help:ArgumentHelp(
					"Assign an IPv4 address for this client.",
					discussion:"This address will be randomly generated and printed in standard output."
				)
			)
			var ipv4:Bool = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() async throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				
				try domainName.promptInteractivelyIfNecessary(db:daemonDB)
				guard try daemonDB.wireguardDatabase.validateNewClientName(subnet:domainName.domain!, clientName:domainName.name!) == true else {
					fatalError("the client name '\(domainName.name!)' cannot be used")
				}
				
				let newKeys = try await WireguardExecutor.generateClient()
				
				var usePublicKey:String
				if (publicKey == nil) {
					usePublicKey = newKeys.publicKey
				} else {
					usePublicKey = publicKey!
				}
				
				let (newClientAddress, optionalV4) = try daemonDB.wireguardDatabase.clientMake(name:domainName.name!, publicKey:usePublicKey, subnet:domainName.domain!, ipv4:ipv4)
				
				let (wg_dns_name, wg_port, wg_internal_network, serverV4, serverPub, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()

				var buildKey = "[Interface]\n"
				if publicKey == nil {
					buildKey += "PrivateKey = " + newKeys.privateKey + "\n"
				}
				buildKey += "Address = " + newClientAddress.string + "/128\n"
				if optionalV4 != nil {
					buildKey += "Address = " + optionalV4!.string + "/32\n"
				}
				if noDNS == false {
					buildKey += "DNS = " + wg_internal_network.address.string + "\n"
				}
				buildKey += "[Peer]\n"
				buildKey += "PublicKey = " + serverPub + "\n"
				buildKey += "PresharedKey = " + newKeys.presharedKey + "\n"
				buildKey += "AllowedIPs = " + wg_internal_network.cidrString
				if (optionalV4 != nil) {
					buildKey += ", \(serverV4)/32\n"
				} else {
					buildKey += "\n"
				}
				buildKey += "Endpoint = " + wg_dns_name + ":\(wg_port)" + "\n"
				buildKey += "PersistentKeepalive = 25" + "\n"
				
				try await WireguardExecutor.install(publicKey:usePublicKey, presharedKey:newKeys.presharedKey, address:newClientAddress, addressv4:optionalV4, interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
				try daemonDB.wireguardDatabase.serveConfiguration(buildKey, forPublicKey:usePublicKey)
				let subnetHash = try WiremanD.hash(domain:domainName.domain!).addingPercentEncoding(withAllowedCharacters:.alphanumerics)!
				let buildURL = "\nhttps://\(domainName.domain!)/wg_getkey?dk=\(subnetHash)&pk=\(usePublicKey.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
				print("\(buildURL)")
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
				try await DNSmasqExecutor.reload()
			}
		}
		
		struct List:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"list the clients that are authorized to connect to this server."
			)
			
			@Option(help:ArgumentHelp(
				"Filter the list to a specified domain."
			))
			var domain:String? = nil
			
			@Flag(
				name:.shortAndLong,
				help:ArgumentHelp("Print IPv6 addresses in a Windows-friendly format.")
			)
			var windowsLegacy = false
			
			@OptionGroup
			var globals:GlobalCLIOptions
			
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				var allClients = try daemonDB.wireguardDatabase.allClients()
				if (domain != nil) {
					allClients = allClients.filter({ $0.subnetName.lowercased() == domain!.lowercased() })
				}
				let subnetGroup = Dictionary(grouping:allClients, by: { $0.subnetName })
				let iterateList = (daemonDB.readOnly == false) ? subnetGroup.sorted(by: { $0.key < $1.key }) : subnetGroup.shuffled()
				let nowDate = Date()
				for subnetToList in iterateList {
					// print the domain name
					if daemonDB.readOnly == false {
						print(Colors.Yellow("\(subnetToList.key)"))
					} else {
						let hashedSubnet = try Blake2bHasher.hash(Data(subnetToList.key.utf8), outputLength:8)
						let hashString = hashedSubnet.base64EncodedString()
						print(Colors.Yellow("\(hashString)"))
					}
					
					// print the sorted clients
					let sortedClients = subnetToList.value.sorted(by: { $0.name < $1.name })
					for curClient in sortedClients {
						if (curClient.lastHandshake == nil) {
							// print the name in dim text since the client has never successfully handshaken
							print(Colors.dim("- \(curClient.name)"), terminator:"\n")
						} else {
							if (curClient.lastHandshake!.timeIntervalSinceNow > -150) {
								// print the name in green text since the client is online
								print(Colors.Green("- \(curClient.name)"), terminator:"")
								
								// endpoint info
								if let hasEndpoint = curClient.endpoint {
									if case let IPDatabase.ResolveStatus.resolved(resInfo) = try daemonDB.ipdb.getResolveStatus(address:hasEndpoint) {
										if let hasCity = resInfo.city, let hasState = resInfo.region?.code {
											print(Colors.dim("\n - Connected from \(hasCity), \(hasState) at \(hasEndpoint)"), terminator:"")
										} else if let hasState = resInfo.region?.name {
											print(Colors.dim("\n - Connected from \(hasState) at \(hasEndpoint)"), terminator:"")
										}
									} else {
										print(Colors.dim("\n - Connected at \(hasEndpoint)"), terminator:"")
									}
								} else {
									print(Colors.dim("\n - Connected at unknown endpoint"), terminator:"")
								}
							} else if curClient.invalidationDate.timeIntervalSinceNow < 43200 {
								// print the name in red text since the client is going to be revoked soon
								print(Colors.Red("- \(curClient.name)"), terminator:"")
							} else {
								// print the name in white text because the client has successfully made a handshake in the past, but is currently offline
								print("- \(curClient.name)", terminator:"")
								
								// endpoint info
								print(Colors.dim("\n - \(curClient.lastHandshake!.relativeTimeString(to:nowDate).lowercased()) "), terminator:"")
								if let hasEndpoint = curClient.endpoint {
									if case let IPDatabase.ResolveStatus.resolved(resInfo) = try daemonDB.ipdb.getResolveStatus(address:hasEndpoint) {
										if let hasCity = resInfo.city, let hasState = resInfo.region?.code {
											print(Colors.dim("from \(hasCity), \(hasState) at \(hasEndpoint)"), terminator:"")
										} else if let hasState = resInfo.region?.name {
											print(Colors.dim("from \(hasState) at \(hasEndpoint)"), terminator:"")
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
								print(Colors.dim(" - \(curClient.address.string)"), terminator:"")
							} else {
								let replaceString = curClient.address.string.replacingOccurrences(of:":", with:"-") + ".ipv6-literal.net"
								print(Colors.cyan("  - \(replaceString)"), terminator:"")
							}
							if (curClient.addressV4 != nil) {
								print(Colors.dim(" & \(curClient.addressV4!.string)"), terminator:"")
							}
							
							// print the public key of the client
							print(Colors.dim("\n - Public key: \(curClient.publicKey)"))
						} 
					}
				}
			}
		}
		
		struct Rename:ParsableCommand {
			static let configuration = CommandConfiguration(
				abstract:"modify the name of an existing client within its domain."
			)
			
			@Argument(help:ArgumentHelp(
				"The public key of the client that is to be renamed."
			))
			var publicKey:String
			
			@Argument(help:ArgumentHelp(
				"The new name to assign to the client."
			))
			var newName:String
			
			@OptionGroup
			var globals:GlobalCLIOptions
						
			mutating func run() throws {
				let daemonDB = try DaemonDB(globals)
				guard daemonDB.readOnly == false else {
					throw CLI.Error.insufficientPrivilege
				}
				try daemonDB.wireguardDatabase.clientRename(publicKey:publicKey, name:newName)
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
		var domain:String? = nil
		
		@Option(
			name:.shortAndLong,
			help:ArgumentHelp(
				"The name of the client."
			)
		)
		var name:String? = nil
		
		mutating func promptInteractivelyIfNecessary(db daemonDB:DaemonDB) throws {
			// determine the domain to use
			if (domain == nil || domain!.count == 0) {
				let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
				switch allSubnets.count {
					case 0:
						print(Colors.Red("There are no subnets configured (this should not be the case)"))
					case 1:
						domain = allSubnets.first!.name
					default:
						print("Please select a domain for this action:")
						for curSub in allSubnets {
							print(Colors.dim("  - \(curSub.name)"))
						}
						repeat {
							print("Domain name: ", terminator:"")
							domain = readLine()
						} while domain == nil || domain!.count == 0
				}
			}
			guard try daemonDB.wireguardDatabase.validateSubnet(name:domain!) == true else {
				print(Colors.Red("The domain name '\(domain!)' does not exist"))
				throw CLI.Client.Error.notFound
			}
			
			// determine the name to use
			if (name == nil || name!.count == 0) {
				let allClients = try daemonDB.wireguardDatabase.allClients(subnet:domain!)
				switch allClients.count {
					case 0:
						print(Colors.Yellow("There are no clients on this subnet yet."))
						throw CLI.Client.Error.notFound
					default:
						print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
						for curClient in allClients {
							print(Colors.dim("\t-\t\(curClient.name)"))
						}
				}
				repeat {
					print("Client name: ", terminator:"")
					name = readLine()
				} while name == nil && name!.count == 0
			}
		}
	}
}