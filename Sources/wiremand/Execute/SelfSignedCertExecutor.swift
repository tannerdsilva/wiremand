import Foundation
import wiremand_databases
import Logging
import SwiftSlash

struct SelfSignedCertExecutor {
	enum Error: Swift.Error {
		case opensslCommandFailed
		case unableToCreateDir
		case unableToGenerateCert
	}
	
	static let certBaseDir = "/etc/wiremand/ssl"
	
	static func generateCert(interfaceName: String, logLevel: Logger.Level) async throws {
		var log = Logger(label: "self-signed-cert-executor")
		log.logLevel = logLevel
		
		let fullchainPath = "/fullchain.pem"
		let privkeyPath = "/privkey.pem"
		
		// Generate a self-signed certificate valid for 10 years
		// -x509: self-signed, -nodes: no passphrase, -days 3650: 10 years
		let certCmd = try await Command(sh:
			"sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 " +
			"-keyout '\(privkeyPath)' -out '\(fullchainPath)' " +
			"-subj \"/CN=\(interfaceName)\" -addext \"subjectAltName=DNS:\(interfaceName)\"",
			environment: CurrentEnvironment.environmentVariables()
		).runSync()
		
		guard certCmd.succeeded else {
			let stderr = String(bytes: certCmd.stderr[0], encoding: .utf8) ?? "unknown error"
			log.error("openssl command failed", metadata: ["stderr": "\(stderr)"])
			throw Error.unableToGenerateCert
		}
		
		let _ = try await Command(sh: "sudo chmod 644 '\(fullchainPath)' '\(privkeyPath)'", environment: CurrentEnvironment.environmentVariables()).runSync()
		
		log.info("self-signed certificate generated")
	}
}
