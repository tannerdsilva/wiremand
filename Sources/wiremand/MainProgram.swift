import Foundation
import Commander
import AddressKit
import SystemPackage
import SwiftSlash
import QuickLMDB
import Logging
import SignalStack
import SwiftSMTP
import SwiftDate
import SwiftBlake2

extension NetworkV6 {
	func maskingAddress() -> NetworkV6 {
		return NetworkV6(address:AddressV6(self.address.integer & self.netmask.integer), netmask:self.netmask)!
	}
}

@main
struct WiremanD {
	static func getCurrentUser() -> String {
		return String(validatingUTF8:getpwuid(geteuid()).pointee.pw_name) ?? ""
	}
	static func getCurrentDatabasePath() -> URL {
		return URL(fileURLWithPath:String(cString:getpwnam("wiremand").pointee.pw_dir))
	}
	static func hash(domain:String) throws -> String {
		let domainData = domain.lowercased().data(using:.utf8)!
		return try Blake2bHasher.hash(domainData, outputLength:64).base64EncodedString()
	}
	static func initializeProcess() {
		umask(000)
		Self.appLogger.trace("process umask cleared", metadata:["mode":"000"])
		#if DEBUG
		appLogger.logLevel = .trace
		#else
		appLogger.logLevel = .info
		#endif
	}
	static var appLogger = Logger(label:"wiremand")
	
	static func permissionsExit() -> Never {
		appLogger.critical("this function requires the current user to have read/write permissions")
		exit(69)
	}

	static func main() async throws {
		initializeProcess()
		await AsyncGroup {
			$0.command("punt",
			   Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
			  Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
		   ) { subnet, name in
			   let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
			   var useSubnet:String? = subnet
			   if (useSubnet == nil || useSubnet!.count == 0) {

				   let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
				   switch allSubnets.count {
					   case 0:
						   fatalError("there are no subnets configured (this should not be the case)")
					   case 1:
						   print("There is only one subnet configured - it has been automatically selected.")
						   useSubnet = allSubnets.first!.name
					   default:
						   print("Please select the subnet of the client you would like to remove:")
						   for curSub in allSubnets {
							   print(Colors.dim("\t-\t\(curSub.name)"))
						   }
						   repeat {
							   print("subnet name: ", terminator:"")
							   useSubnet = readLine()
						   } while useSubnet == nil || useSubnet!.count == 0
				   }
			   }
			   guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
				   fatalError("the subnet name '\(useSubnet!)' does not exist")
			   }
			   
			   var useClient:String? = name
			   if (useClient == nil || useClient!.count == 0) {
				   let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
				   switch allClients.count {
					   case 0:
						   print(Colors.Yellow("There are no clients on this subnet yet."))
						   exit(1)
					   default:
						   print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
						   for curClient in allClients {
							   print(Colors.dim("\t-\t\(curClient.name)"))
						   }
				   }
				   repeat {
					   print("client name (optional): ", terminator:"")
					   useClient = readLine()
				   } while useClient == nil
			   }
				
				
				let newInvalidDate:Date
				if (useClient!.count == 0) {
					appLogger.debug("punting all clients in subnet", metadata:["subnet": "\(useSubnet!)"]);
					do {
						newInvalidDate = try daemonDB.wireguardDatabase.puntAllClients(subnet:useSubnet!)
					} catch LMDBError.notFound {
						appLogger.error("no clients exist under this subnet. nothing to punt.")
						exit(1)
					}
				} else {
					appLogger.debug("punting individual client", metadata:["subnet": "\(useSubnet!)", "client": "\(useClient!)"])
					newInvalidDate = try daemonDB.wireguardDatabase.puntClientInvalidation(subnet:useSubnet!, name:useClient!)
				}
				appLogger.info("successfully punted", metadata:["now invalidating on": "\(newInvalidDate)"])
			}
			
			$0.command("printer_make",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to authorized"),
			   Option<String?>("subnet", default:nil, description:"the subnet name that the printer will be assigned to")
			) { mac, subnet in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				guard let pdb = daemonDB.printerDatabase else {
					fatalError("the printer functionality is not enabled")
				}
				// ask for the subnet if needed
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {
					print("Please chose a subnet for this printer:")
					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					for curSub in allSubnets {
						print(Colors.dim("\t-\t\(curSub.name)"))
					}
					repeat {
						print("subnet name: ", terminator:"")
						useSubnet = readLine()
					} while useSubnet == nil || useSubnet!.count == 0
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address for the new printer:")
					let allAuthorized = Dictionary(grouping:try pdb.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				let printerMetadata = try pdb.authorizeMacAddress(mac:useMac!.lowercased(), subnet:useSubnet!)
				print(Colors.Green("[OK] - Printer assigned to \(useSubnet!)"))
				print(Colors.Yellow("\tPrinter username: - \(printerMetadata.username)"))
				print(Colors.Yellow("\tPrinter password: - \(printerMetadata.password)"))
				print(" - - - - - - - - - - - - - - - - - ")
				print(Colors.Cyan("\tServer print port: \(printerMetadata.port)"))
				print(Colors.Cyan("\tServer print address: \(try daemonDB.wireguardDatabase.getServerInternalNetwork().address.string)"))
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("printer_revoke",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to authorized")
			) { mac in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				guard let pdb = daemonDB.printerDatabase else {
					fatalError("the printer functionality is not enabled")
				}
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address to revoke:")
					let allAuthorized = Dictionary(grouping:try pdb.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				
				try pdb.deauthorizeMacAddress(mac:useMac!)
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("printer_list") {
				let daemonDB = try DaemonDB(running:false)
				guard let pdb = daemonDB.printerDatabase else {
					fatalError("the printer functionality is not enabled")
				}
				let allAuthorized = Dictionary(grouping:try pdb.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
				for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
					print(Colors.Yellow("- \(curSub.key)"))
					for curMac in curSub.value {
						print(Colors.dim("\t-\t\(curMac.mac)"))
						let statusInfo = try pdb.getPrinterStatus(mac:curMac.mac)
						print("\t-> Last Connected: \(statusInfo.lastSeen)")
						print("\t-> Status: \(statusInfo.status)")
						print("\t-> \(statusInfo.jobs.count) Pending Jobs: \(statusInfo.jobs.sorted(by: { $0 < $1 }))")
					}
				}
			}
			
			$0.command("printer_set_cutmode",
			   Option<String?>("mac", default:nil, description:"the mac address of the printer to edit the cut mode"),
				Option<String?>("cut", default:nil, description:"the cut mode to assign to the printer. may be 'full', 'partial', or 'none'")
			) { mac, cut in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				guard let pdb = daemonDB.printerDatabase else {
					fatalError("the printer functionality is not enabled")
				}
				var useMac:String? = mac
				if (useMac == nil || useMac!.count == 0) {
					print("Please enter a MAC address to edit:")
					let allAuthorized = Dictionary(grouping:try pdb.getAuthorizedPrinterInfo(), by: { $0.subnet }).compactMapValues({ $0.sorted(by: { $0.mac < $1.mac }) })
					for curSub in allAuthorized.sorted(by: { $0.key < $1.key }) {
						print(Colors.Yellow("- \(curSub.key)"))
						for curMac in curSub.value {
							print(Colors.dim("\t-\t\(curMac.mac)"))
						}
					}
					repeat {
						print("MAC address: ", terminator:"")
						useMac = readLine()
					} while useMac == nil || useMac!.count == 0
				}
				
				var useCut:String? = cut
				if (useCut == nil || useCut!.count == 0) {
					repeat {
						print("Cut mode [ full | partial | none ]: ", terminator:"")
						useCut = readLine()
					} while PrintDB.CutMode(rawValue:useCut!) == nil
				}
				guard let cutMode = PrintDB.CutMode(rawValue:useCut!) else {
					appLogger.critical("Invalid cut mode specified")
					exit(5)
				}
				try pdb.assignCutMode(mac:useMac!, mode:cutMode)
				try daemonDB.reloadRunningDaemon()
			}
			
			$0.command("client_provision_v4",
				Option<String?>("subnet", default:nil, description:"the name of the subnet that the client belongs to"),
				Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
			) { subnet, name in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useClient:String? = name
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
							exit(1)
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				let (_, _, _, _, _, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()
				let (newV4, curV6, pubString) = try daemonDB.wireguardDatabase.clientAssignIPv4(subnet:useSubnet!, name:useClient!)
				try await WireguardExecutor.updateExistingClient(publicKey:pubString, with:curV6, and:newV4, interfaceName:interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName: interfaceName)
				
				print("On the client [Peer], please update allowed-ips to the following value:\n")
				print("AllowedIPs=\(curV6.string)/128,\(newV4.string)/32")
			}
			
			$0.command("client_revoke",
			   Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
			   Option<String?>("name", default:nil, description:"the name of the client that the key will be created for")
			) { subnet, name in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				var useSubnet:String? = subnet
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}
				
				var useClient:String? = name
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
							exit(1)
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				try daemonDB.wireguardDatabase.clientRemove(subnet:useSubnet!, name:useClient!)
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
			}
			
			$0.command("client_make",
				Option<String?>("subnet", default:nil, description:"the name of the subnet to assign the new user to"),
				Option<String?>("name", default:nil, description:"the name of the client that the key will be created for"),
				Option<String?>("publicKey", default:nil, description:"the public key of the client that is being added"),
				Flag("noDNS", default:false, description:"do not include DNS information in the configuration"),
				Flag("ipv4", default:false, description:"assign this client an ipv4 address as well as an ipv6 address")
			) { subnetName, clientName, pk, noDNS, withIPv4 in
				let daemonDB = try DaemonDB(running:false)
				guard daemonDB.readOnly == false else {
					permissionsExit()
				}
				var useSubnet:String? = subnetName
				if (useSubnet == nil || useSubnet!.count == 0) {

					let allSubnets = try daemonDB.wireguardDatabase.allSubnets()
					switch allSubnets.count {
						case 0:
							fatalError("there are no subnets configured (this should not be the case)")
						case 1:
							print("There is only one subnet configured - it has been automatically selected.")
							useSubnet = allSubnets.first!.name
						default:
							print("Please select the subnet of the client you would like to remove:")
							for curSub in allSubnets {
								print(Colors.dim("\t-\t\(curSub.name)"))
							}
							repeat {
								print("subnet name: ", terminator:"")
								useSubnet = readLine()
							} while useSubnet == nil || useSubnet!.count == 0
					}
				}
				guard try daemonDB.wireguardDatabase.validateSubnet(name:useSubnet!) == true else {
					fatalError("the subnet name '\(useSubnet!)' does not exist")
				}

				var useClient:String? = clientName
				if (useClient == nil || useClient!.count == 0) {
					let allClients = try daemonDB.wireguardDatabase.allClients(subnet:useSubnet)
					switch allClients.count {
						case 0:
							print(Colors.Yellow("There are no clients on this subnet yet."))
						default:
							print(Colors.Yellow("There are \(allClients.count) clients on this subnet:"))
							for curClient in allClients {
								print(Colors.dim("\t-\t\(curClient.name)"))
							}
					}
					repeat {
						print("client name: ", terminator:"")
						useClient = readLine()
					} while useClient == nil && useClient!.count == 0
				}
				guard try daemonDB.wireguardDatabase.validateNewClientName(subnet:useSubnet!, clientName:useClient!) == true else {
					fatalError("the client name '\(useClient!)' cannot be used")
				}
				
				// we will make the keys on behalf of the client
				let newKeys = try await WireguardExecutor.generateClient()
				
				var usePublicKey:String? = pk
				let usePSK:String = newKeys.presharedKey
				if (usePublicKey == nil) {
					usePublicKey = newKeys.publicKey
				}
				
				let (newClientAddress, optionalV4) = try daemonDB.wireguardDatabase.clientMake(name:useClient!, publicKey:usePublicKey!, subnet:useSubnet!, ipv4:withIPv4)
				
				let (wg_dns_name, wg_port, wg_internal_network, serverV4, serverPub, interfaceName) = try daemonDB.wireguardDatabase.getWireguardConfigMetas()
				
				var buildKey = "[Interface]\n"
				if pk == nil {
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
				
				try await WireguardExecutor.install(publicKey: usePublicKey!, presharedKey: usePSK, address: newClientAddress, addressv4:optionalV4, interfaceName: interfaceName)
				try await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
				try daemonDB.wireguardDatabase.serveConfiguration(buildKey, forPublicKey:usePublicKey!)
				let subnetHash = try WiremanD.hash(domain:useSubnet!).addingPercentEncoding(withAllowedCharacters:.alphanumerics)!
				let buildURL = "\nhttps://\(useSubnet!)/wg_getkey?dk=\(subnetHash)&pk=\(usePublicKey!.addingPercentEncoding(withAllowedCharacters:.alphanumerics)!)\n"
				print("\(buildURL)")
				try DNSmasqExecutor.exportAutomaticDNSEntries(db:daemonDB)
				try await DNSmasqExecutor.reload()
			}
			
			$0.command("client_list",
				Option<String?>("subnet", default:nil, description:"the name of the subnet that you would like to view the clients of."),
				Flag("windowsLegacy", default:false, flag:"w", description:"print client IPv6 addresses in as a DNS name that is Windows friendly.")
			) { subnetString, printWindowsLiteral in
				let start = Date()
				let daemonDB = try DaemonDB(running:false)
				if daemonDB.readOnly == true {
					guard subnetString != nil else {
						Self.appLogger.critical("a subnet must be specified with the --subnet flag")
						exit(70)
					}
				}
				var allClients = try daemonDB.wireguardDatabase.allClients()
				if (subnetString != nil) {
					allClients = allClients.filter({ $0.subnetName.lowercased() == subnetString!.lowercased() })
				}
				let subnetSort = Dictionary(grouping:allClients, by: { $0.subnetName })
				let nowDate = Date()
				var cliCount:UInt64 = 0
				for subnetToList in subnetSort.sorted(by: { $0.key < $1.key }) {
					print(Colors.Yellow("\(subnetToList.key)"))
					let sortedClients = subnetToList.value.sorted(by: { $0.name < $1.name })
					for curClient in sortedClients {
						cliCount += 1;
						// print the online status
						if (curClient.lastHandshake == nil) {
							// name
							print(Colors.dim("- \(curClient.name)"), terminator:"")
						} else {
							
							if curClient.lastHandshake!.timeIntervalSinceNow > -150 {
								//name
								print(Colors.Green("- \(curClient.name)"), terminator:"")
								
								// endpoint info
								if let hasEndpoint = curClient.endpoint {
									if case let IPDatabase.ResolveStatus.resolved(resInfo) = try daemonDB.ipdb.getResolveStatus(address:hasEndpoint) {
										if let hasCity = resInfo.city, let hasState = resInfo.region?.code {
											print(Colors.dim("\n  - Connected from \(hasCity), \(hasState) at \(hasEndpoint)"), terminator:"")
										} else if let hasState = resInfo.region?.name {
											print(Colors.dim("\n  - Connected from \(hasState) at \(hasEndpoint)"), terminator:"")
										}
									} else {
										print(Colors.dim("\n  - Connected at \(hasEndpoint)"), terminator:"")
									}
								} else {
									print(Colors.dim("\n  - Connected at unknown endpoint"), terminator:"")
								}
								
							} else if curClient.invalidationDate.timeIntervalSinceNow < 43200 {
								// name
								print(Colors.Red("- \(curClient.name)"), terminator:"")
							} else {
								// name
								print("- \(curClient.name)", terminator:"")
								
								// endpoint info
								print(Colors.dim("\n  - \(curClient.lastHandshake!.relativeTimeString(to:nowDate).lowercased()) "), terminator:"")
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
							if (printWindowsLiteral == false) {
								print(Colors.dim("  - \(curClient.address.string)"), terminator:"")
							} else {
								let replaceString = curClient.address.string.replacingOccurrences(of:":", with:"-") + ".ipv6-literal.net"
								print(Colors.cyan("  - \(replaceString)"), terminator:"")
							}
							if (curClient.addressV4 != nil) {
								print(Colors.dim(" & \(curClient.addressV4!.string)"), terminator:"")
							}
							
							// print the public key of the client
							print(Colors.dim("\n  - Public key: \(curClient.publicKey)"))
						}
					}
				}
				
				let time = start.timeIntervalSinceNow
				let timeString = String(format:"%.4f", abs(time))
			
				print(Colors.dim(" - - - - - - - - - - - - - - - - "))
				print(Colors.dim(" * listed \(cliCount) clients in \(timeString) seconds * "))
			}
							
			$0.command("run") {
				enum Error:Swift.Error {
					case handshakeCheckError
					case endpointCheckError
					case databaseActionError
					case noEndpointProvided
				}
				guard getCurrentUser() == "wiremand" else {
					fatalError("this function must be run as the wiremand user")
				}
				let daemonDB = try DaemonDB(running:true)
				await SignalStack.global.add(signal: SIGHUP, { _ in
					if let hasPDB = daemonDB.printerDatabase {
						Task.detached { [hasPDB] in
							appLogger.info("port sync triggered")
							try await hasPDB.portSync()
						}
					}
				})
				let interfaceName = try daemonDB.wireguardDatabase.primaryInterfaceName()
				let tcpPortBind = try daemonDB.wireguardDatabase.getServerInternalNetwork().address.string
				
				// schedule the handshake checker
				try daemonDB.launchSchedule(.latestWireguardHandshakesCheck, interval:10, { [wgdb = daemonDB.wireguardDatabase, logger = appLogger] in
					do {
						// run the shell command to check for the handshakes associated with the various public keys
						let checkHandshakes = try await Command(bash:"sudo wg show \(interfaceName) latest-handshakes").runSync()
						guard checkHandshakes.succeeded == true else {
							throw Error.handshakeCheckError
						}

						// interpret the handshake data
						// nonzero handhakes will be stored here
						var handshakes = [String:Date]()
						// zero handshakes will be stored here
						var zeros = Set<String>()
						for curLine in checkHandshakes.stdout {
							// split the data by tabs
							let splitLine = curLine.split(separator:9)
							// validate the data between the split
							guard splitLine.count > 1, let publicKeyString = String(data:splitLine[0], encoding:.utf8), let handshakeTime = String(data:splitLine[1], encoding:.utf8), let asTimeInterval = TimeInterval(handshakeTime) else {
								throw Error.handshakeCheckError
							}

							// assign the public key to either the nonzero or zero handshakes variables
							if asTimeInterval == 0 {
								zeros.update(with:publicKeyString)
							} else {
								handshakes[publicKeyString] = Date(timeIntervalSince1970:asTimeInterval)
							}
						}
						
						// run the shell command to check for the endpoints of each client
						var endpoints = [String:String]()
						let checkEndpoints = try await Command(bash:"sudo wg show \(interfaceName) endpoints").runSync()
						guard checkEndpoints.succeeded == true else {
							Self.appLogger.error("was not able to check wireguard client endpoints")
							throw Error.endpointCheckError
						}
						
						for curEndpointLine in checkEndpoints.stdout {
							do {
								guard let lineString = String(data:curEndpointLine, encoding:.utf8), let tabSepIndex = lineString.firstIndex(of:"\t"), lineString.endIndex > tabSepIndex else {
									Self.appLogger.error("invalid line data - no tab break found")
									throw Error.endpointCheckError
								}
								
								let pubKeySectComplete = String(lineString[lineString.startIndex..<tabSepIndex])
								let addrSectComplete = lineString[lineString.index(after:tabSepIndex)..<lineString.endIndex]
								
								Self.appLogger.trace("parsed endpoint data line", metadata:["pubKey":"\(pubKeySectComplete)", "addr":"\(addrSectComplete)"])
								
								guard let portSepIndex = addrSectComplete.lastIndex(of:":"), portSepIndex < addrSectComplete.endIndex else {
									Self.appLogger.trace("client does not have an endpoint", metadata:["pubKey":"\(pubKeySectComplete)"])
									throw Error.noEndpointProvided
								}
								let addrSect = String(addrSectComplete[addrSectComplete.startIndex..<portSepIndex])
								let portSect = String(addrSectComplete[addrSectComplete.index(after:portSepIndex)..<addrSectComplete.endIndex])
								
								guard addrSect.count > 0 && portSect.count > 0 else {
									Self.appLogger.error("unable to parse data line. zero counts were identified", metadata:["addrSect_count": "\(addrSect.count)", "portSect_count": "\(portSect.count)"])
									throw Error.endpointCheckError
								}
								
								guard let _ = UInt16(portSect) else {
									Self.appLogger.error("unable to parse endpoint port", metadata:["port_string": "'\(portSect)'", "string_count": "\(portSect.count)"])
									throw Error.endpointCheckError
								}
								
								// determine if ipv6
								if (addrSect.first == "[" && addrSect.last == "]" && addrSect.contains(":") == true) {
									// ipv6
									let asStr = String(addrSect[addrSect.index(after:addrSect.startIndex)..<addrSect.index(before:addrSect.endIndex)])
									guard let asV6 = AddressV6(asStr) else {
										Self.appLogger.error("unable to parse IPv6 address from wireguard endpoints output", metadata:["ip": "\(asStr)"])
										throw Error.endpointCheckError
									}
									
									endpoints[pubKeySectComplete] = asV6.string
								} else if addrSect.contains(".") == true {
									// ipv4
									guard let asV4 = AddressV4(addrSect) else {
										Self.appLogger.error("unable to parse IPv4 address from wireguard endpoints output", metadata:["ip": "\(addrSect)"])
										throw Error.endpointCheckError
									}
									
									endpoints[pubKeySectComplete] = asV4.string
								} else {
									throw Error.endpointCheckError
								}
							} catch Error.noEndpointProvided {
							}
						}
						
						// save the handshake data to the database
						let takeActions = try wgdb.processHandshakes(handshakes, endpoints:endpoints, all:Set(handshakes.keys).union(zeros))
						var rmI = 0
						for curAction in takeActions {
							switch curAction {
								case let .removeClient(pubKey):
									try? await WireguardExecutor.uninstall(publicKey:pubKey, interfaceName:interfaceName)
									rmI += 1
								case let .resolveIP(ipAddr):
									switch ipAddr.contains(":") {
										case true:
											guard let asAddr = AddressV6(ipAddr) else {
												Self.appLogger.error("unable to parse ipv6 address from database action", metadata:["ip_str":"\(ipAddr)"])
												throw Error.databaseActionError
											}
											try daemonDB.ipdb.installAddress(ipv6:asAddr)
										case false:
											guard let asAddr = AddressV4(ipAddr) else {
												Self.appLogger.error("unable to parse ipv4 address from database action", metadata:["ip_str":"\(ipAddr)"])
												throw Error.databaseActionError
											}
											try daemonDB.ipdb.installAddress(ipv4:asAddr)
									}
							}
						}
						
						if (rmI > 0) {
							try? await WireguardExecutor.saveConfiguration(interfaceName:interfaceName)
						}
					} catch let error {
						logger.error("handshake check error", metadata:["error": "\(error)"])
					}
				})
				
				// schedule the ssl renewal
				try daemonDB.launchSchedule(.certbotRenewalCheck, interval:172800) { [logger = appLogger] in
					do {
						try await CertbotExecute.renewCertificates()
						_ = try await NginxExecutor.reload()
					} catch let error {
						logger.error("ssl certificates could not be renewed", metadata:["error": "\(error)"])
					}
				}
				
				var allPorts = [UInt16:TCPServer]()
				try! await daemonDB.printerDatabase!.assignPortHandlers(opener: { newPort, _ in
					let newServer = try TCPServer(host:tcpPortBind, port:newPort, db:daemonDB.printerDatabase!)
					allPorts[newPort] = newServer
				}, closer: { oldPort in
					allPorts[oldPort] = nil
				})
				let webserver = try PublicHTTPWebServer(daemonDB:daemonDB, pp:daemonDB.printerDatabase!, port:daemonDB.getPublicHTTPPort())
				try webserver.run()
				webserver.wait()
			}
		}.run()
	}
}
