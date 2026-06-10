import ServiceLifecycle
import wiremand_databases
import Logging
import Foundation
import SwiftSlash
import bedrock
import bedrock_ip

final class IPStacker: Service {
	enum Error:Swift.Error {
		case invalidUserPublicKey
		case handshakeCheckError
		case endpointCheckError
		case databaseActionError
		case noEndpointProvided
	}
	
	private let logger: Logger
		
	private let ipdb:IPDatabase
	private let scheduler: Scheduler
	private let taskName = EncodedString("fetch-ipstack-information")
		
	init(ipdb:IPDatabase, logLevel: Logger.Level) throws {
		var log = Logger(label:"\(String(describing:Self.self))")
		log.logLevel = logLevel
		self.logger = log
		let installUserName = "wiremand"
		let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
		self.scheduler = try Scheduler(base: homeDir, log: logger)
		self.ipdb = ipdb
	}
	
	func run() async throws {
		do {
			try await scheduler.runSchedule(name: taskName, interval: .seconds(600)) {
				var accessKeyOptional = try self.ipdb.setupMainLoop()

				while let currentAddress = try self.ipdb.getNextPendingAddress(), let accessKey = accessKeyOptional {
					do {
						let resolvedIPInfo = try await IPDatabase.ResolvedIPInfo.from(addressString:currentAddress, accessKey:accessKey)
						self.logger.debug("successfully resolved IP address", metadata:["ip": "\(currentAddress)"])
						accessKeyOptional = try self.ipdb.installResolved(currentAddress: EncodedString(currentAddress), resolvedIPInfo: resolvedIPInfo)
					} catch let error as IPDatabase.ResolvedIPInfo.Error {
						self.logger.debug("failed to resolve IP address", metadata:["ip": "\(currentAddress)"])
						try self.ipdb.uninstallPending(addressString: EncodedString(currentAddress))
						try self.ipdb.installFailedResolve(address: currentAddress, error: error)
					}
				}
			}
		} catch {
		   logger.error("Scheduler failed", metadata: ["error": "\(error)"])
		   throw error
		}
		logger.info("IPStacker service shut down")
	}
}
