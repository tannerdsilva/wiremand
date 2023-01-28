import ArgumentParser
import AddressKit
import QuickLMDB
import Logging
import Foundation
import SwiftSlash
import bedrock
import SignalStack

extension CLI {
	struct Run:AsyncParsableCommand {
		enum Error:Swift.Error {
			case invalidUser
			case handshakeCheckError
			case endpointCheckError
			case databaseActionError
			case noEndpointProvided
		}

		static let configuration = CommandConfiguration(
			abstract:"run the daemon process"
		)
		
		@OptionGroup
		var globals:GlobalCLIOptions
		
		mutating func run() async throws {
			umask(000)
			var appLogger = Logger(label:"wiremand")
			appLogger.logLevel = globals.logLevel

			guard getCurrentUser() == "wiremand" else {
				print("this function must be run as the wiremand user")
				throw Error.invalidUser
			}
			let daemonDB = try DaemonDB(globals, running:true)
			await SignalStack.global.add(signal: SIGHUP, { _ in
				if let hasPDB = daemonDB.printerDatabase {
					Task.detached { [hasPDB, logger = appLogger] in
						logger.info("port sync triggered")
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
						logger.error("was not able to check wireguard client endpoints")
						throw Error.endpointCheckError
					}
					
					for curEndpointLine in checkEndpoints.stdout {
						do {
							guard let lineString = String(data:curEndpointLine, encoding:.utf8), let tabSepIndex = lineString.firstIndex(of:"\t"), lineString.endIndex > tabSepIndex else {
								logger.error("invalid line data - no tab break found")
								throw Error.endpointCheckError
							}
							
							let pubKeySectComplete = String(lineString[lineString.startIndex..<tabSepIndex])
							let addrSectComplete = lineString[lineString.index(after:tabSepIndex)..<lineString.endIndex]
							
							logger.trace("parsed endpoint data line", metadata:["pubKey":"\(pubKeySectComplete)", "addr":"\(addrSectComplete)"])
							
							guard let portSepIndex = addrSectComplete.lastIndex(of:":"), portSepIndex < addrSectComplete.endIndex else {
								logger.trace("client does not have an endpoint", metadata:["pubKey":"\(pubKeySectComplete)"])
								throw Error.noEndpointProvided
							}
							let addrSect = String(addrSectComplete[addrSectComplete.startIndex..<portSepIndex])
							let portSect = String(addrSectComplete[addrSectComplete.index(after:portSepIndex)..<addrSectComplete.endIndex])
							
							guard addrSect.count > 0 && portSect.count > 0 else {
								logger.error("unable to parse data line. zero counts were identified", metadata:["addrSect_count": "\(addrSect.count)", "portSect_count": "\(portSect.count)"])
								throw Error.endpointCheckError
							}
							
							guard let _ = UInt16(portSect) else {
								logger.error("unable to parse endpoint port", metadata:["port_string": "'\(portSect)'", "string_count": "\(portSect.count)"])
								throw Error.endpointCheckError
							}
							
							// determine if ipv6
							if (addrSect.first == "[" && addrSect.last == "]" && addrSect.contains(":") == true) {
								// ipv6
								let asStr = String(addrSect[addrSect.index(after:addrSect.startIndex)..<addrSect.index(before:addrSect.endIndex)])
								guard let asV6 = AddressV6(asStr) else {
									logger.error("unable to parse IPv6 address from wireguard endpoints output", metadata:["ip": "\(asStr)"])
									throw Error.endpointCheckError
								}
								
								endpoints[pubKeySectComplete] = asV6.string
							} else if addrSect.contains(".") == true {
								// ipv4
								guard let asV4 = AddressV4(addrSect) else {
									logger.error("unable to parse IPv4 address from wireguard endpoints output", metadata:["ip": "\(addrSect)"])
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
											logger.error("unable to parse ipv6 address from database action", metadata:["ip_str":"\(ipAddr)"])
											throw Error.databaseActionError
										}
										try daemonDB.ipdb.installAddress(ipv6:asAddr)
									case false:
										guard let asAddr = AddressV4(ipAddr) else {
											logger.error("unable to parse ipv4 address from database action", metadata:["ip_str":"\(ipAddr)"])
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
	}
}