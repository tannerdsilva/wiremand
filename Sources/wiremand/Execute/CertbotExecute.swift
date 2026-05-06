import Foundation
import wiremand_databases
import Logging
import SwiftSlash

struct CertbotExecute {
    enum Error:Swift.Error {
        case unableToAcquireSSL([String], [String])
		case unableToUpdateContacts
		case unableToRemoveSSL
		case unableToRenewSSL
    }
	
	static func acquireSSL(domain:String, email:String?) async throws {
		let emailString = email == nil ? "--email none" : "-m \(email!)"
		let acquireSSL = try await Command("sudo certbot certonly --webroot -w /var/www/html -n --agree-tos --no-eff-email \(emailString) -d \(domain)").runSync()
		guard acquireSSL.succeeded == true else {
			throw Error.unableToAcquireSSL(acquireSSL.stdout.compactMap({ String(bytes:$0, encoding:.utf8) }), acquireSSL.stderr.compactMap({ String(bytes:$0, encoding:.utf8) }))
		}
	}
	
	static func removeSSL(domain:String) async throws {
		let removeAction = try await Command("sudo certbot delete -n --cert-name \(domain)").runSync()
		guard removeAction.succeeded == true else {
			throw Error.unableToRemoveSSL
		}
	}
	
	static func renewCertificates(logLevel: Logger.Level) async throws {
		var log = Logger(label: "certbot-executor")
		log.logLevel = logLevel
		let renewAction = try await Command("sudo certbot renew -nq").runSync()
		guard renewAction.succeeded == true else {
			throw Error.unableToRenewSSL
		}
		log.info("ssl certificates successfully renewed")
	}
}
