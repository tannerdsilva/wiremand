import ServiceLifecycle
import wiremand_databases
import Logging
import Foundation
import SwiftSlash
import bedrock
import bedrock_ip

final class HandshakeChecker: Service {
	enum Error:Swift.Error {
		case invalidUserPublicKey
		case handshakeCheckError
		case endpointCheckError
		case databaseActionError
		case noEndpointProvided
	}
	
	private let logger: Logger
	
	private let wgdb:WireguardDatabase
	
	private let ipdb:IPDatabase
	
	private let interfaceName: EncodedString
	
	private let scheduler: Scheduler
	private let taskName = EncodedString("check-wireguard-handshakes")
	
	init(wgdb:WireguardDatabase, ipdb:IPDatabase, interfaceName: EncodedString, logLevel: Logger.Level) throws {
		var log = Logger(label:"\(String(describing:Self.self))")
		log.logLevel = logLevel
		self.logger = log
		let installUserName = "wiremand"
		let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
		self.scheduler = try Scheduler(base: homeDir, log: logger)
		self.wgdb = wgdb
		self.ipdb = ipdb
		self.interfaceName = interfaceName
	}
	
	func run() async throws {
		do {
			try await scheduler.runSchedule(name: taskName, interval: .seconds(10)) {
				do {
					// run the shell command to check for the handshakes associated with the various public keys
					let checkHandshakes = try await Command(sh: "sudo wg show \(String(self.interfaceName)) latest-handshakes", environment: CurrentEnvironment.environmentVariables()).runSync()
					guard checkHandshakes.succeeded == true else {
						throw Error.handshakeCheckError
					}

					// interpret the handshake data
					// nonzero handhakes will be stored here
					var handshakes = [PublicKey:bedrock.Date.Seconds]()
					// zero handshakes will be stored here
					var zeros = Set<PublicKey>()
					for curLine in checkHandshakes.stdout {
						// split the data by tabs
						let splitLine = curLine.split(separator:9)
						// validate the data between the split
						guard splitLine.count > 1,
								let publicKeyString = String(bytes: splitLine[0], encoding: .utf8),
								let handshakeTime   = String(bytes: splitLine[1], encoding: .utf8),
								let asTimeInterval   = TimeInterval(handshakeTime)
						else {
							throw Error.handshakeCheckError
						}

						guard let publicKey = PublicKey(argument: publicKeyString) else {
							throw Error.invalidUserPublicKey
						}
						// assign the public key to either the nonzero or zero handshakes variables
						if asTimeInterval == 0 {
							zeros.update(with:publicKey)
						} else {
							handshakes[publicKey] = bedrock.Date.Seconds(seconds: UInt64(asTimeInterval))
						}
					}
					
					// run the shell command to check for the endpoints of each client
					var endpoints = [PublicKey:Address]()
					let checkEndpoints = try await Command(sh: "sudo wg show \(String(self.interfaceName)) endpoints", environment: CurrentEnvironment.environmentVariables()).runSync()
					guard checkEndpoints.succeeded == true else {
						self.logger.error("was not able to check wireguard client endpoints")
						throw Error.endpointCheckError
					}
					
					for curEndpointLine in checkEndpoints.stdout {
						do {
							guard let lineString = String(bytes:curEndpointLine, encoding:.utf8), let tabSepIndex = lineString.firstIndex(of:"\t"), lineString.endIndex > tabSepIndex else {
								self.logger.error("invalid line data - no tab break found")
								throw Error.endpointCheckError
							}
							
							let pubKeySectComplete = String(lineString[lineString.startIndex..<tabSepIndex])
							guard let publicKey = PublicKey(argument: pubKeySectComplete) else {
								throw Error.invalidUserPublicKey
							}
							let addrSectComplete = lineString[lineString.index(after:tabSepIndex)..<lineString.endIndex]
							
							self.logger.trace("parsed endpoint data line", metadata:["pubKey":"\(pubKeySectComplete)", "addr":"\(addrSectComplete)"])
							
							guard let portSepIndex = addrSectComplete.lastIndex(of:":"), portSepIndex < addrSectComplete.endIndex else {
								self.logger.trace("client does not have an endpoint", metadata:["pubKey":"\(pubKeySectComplete)"])
								throw Error.noEndpointProvided
							}
							let addrSect = String(addrSectComplete[addrSectComplete.startIndex..<portSepIndex])
							let portSect = String(addrSectComplete[addrSectComplete.index(after:portSepIndex)..<addrSectComplete.endIndex])
							
							guard addrSect.count > 0 && portSect.count > 0 else {
								self.logger.error("unable to parse data line. zero counts were identified", metadata:["addrSect_count": "\(addrSect.count)", "portSect_count": "\(portSect.count)"])
								throw Error.endpointCheckError
							}
							
							guard let _ = UInt16(portSect) else {
								self.logger.error("unable to parse endpoint port", metadata:["port_string": "'\(portSect)'", "string_count": "\(portSect.count)"])
								throw Error.endpointCheckError
							}
							
							// determine if ipv6
							if (addrSect.first == "[" && addrSect.last == "]" && addrSect.contains(":") == true) {
								// ipv6
								let asStr = String(addrSect[addrSect.index(after:addrSect.startIndex)..<addrSect.index(before:addrSect.endIndex)])
								guard let asV6 = Address(asStr) else {
									self.logger.error("unable to parse IPv6 address from wireguard endpoints output", metadata:["ip": "\(asStr)"])
									throw Error.endpointCheckError
								}
								
								endpoints[publicKey] = asV6
							} else if addrSect.contains(".") == true {
								// ipv4
								guard let asV4 = Address(addrSect) else {
									self.logger.error("unable to parse IPv4 address from wireguard endpoints output", metadata:["ip": "\(addrSect)"])
									throw Error.endpointCheckError
								}
								
								endpoints[publicKey] = asV4
							} else {
								throw Error.endpointCheckError
							}
						} catch Error.noEndpointProvided { }
					}
					
					// save the handshake data to the database
					let takeActions = try self.wgdb.processHandshakes(handshakes, endpoints:endpoints, all:Set(handshakes.keys).union(zeros))
					var rmI = 0
					for curAction in takeActions {
						switch curAction {
							case let .removeClient(pubKey):
								try? await WireguardExecutor.uninstall(publicKey:pubKey, interfaceName:self.interfaceName)
								rmI += 1
							case let .resolveIP(ipAddr):
								switch ipAddr {
									case .v4(let v4Addr):
										try self.ipdb.installAddress(ipv4:AddressV4(v4Addr))
									case .v6(let v6Addr):
										try self.ipdb.installAddress(ipv6:AddressV6(v6Addr))
								}
						}
					}
					
					if (rmI > 0) {
						try? await WireguardExecutor.saveConfiguration(interfaceName:self.interfaceName, logLevel: self.logger.logLevel)
					}
				} catch let error {
					self.logger.error("handshake check error", metadata:["error": "\(error)"])
				}
			}
		} catch {
			logger.error("Scheduler failed", metadata: ["error": "\(error)"])
			throw error
		}
		logger.info("HandshakeChecker service shut down")
	}
}
