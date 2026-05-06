import ServiceLifecycle
import wiremand_databases
import Foundation
import Logging

final class RenewSSLService: Service {
	
	private let logger: Logger
	private let scheduler: Scheduler
	private let taskName = EncodedString("ssl-cert-renew")
	
	init(logLevel: Logger.Level) throws {
		var log = Logger(label:"\(String(describing:Self.self))")
		log.logLevel = logLevel
		self.logger = log
		let installUserName = "wiremand"
		let homeDir = URL(fileURLWithPath:"/var/lib/\(installUserName)/")
		self.scheduler = try Scheduler(base: homeDir, log: logger)
	}
	
	func run() async throws {
		do {
			try await scheduler.runSchedule(name: taskName, interval: .seconds(172800)) {
				do {
					try await CertbotExecute.renewCertificates(logLevel: logger.logLevel)
					_ = try await NginxExecutor.reload(logLevel: logger.logLevel)
				} catch {
					logger.error("ssl certificates could not be renewed", metadata: ["error": "\(error)"])
				}
			}
		} catch {
		   logger.error("Scheduler failed", metadata: ["error": "\(error)"])
		   throw error
		}
		
		
		logger.info("RenewSSL service shut down")
	}
}
