import Foundation
import SwiftSlash

struct CertbotExecute {
    enum Error:Swift.Error {
        case unableToAcquireSSL([String], [String])
		case unableToUpdateContacts
		case unableToRemoveSSL
    }
	
	static func acquireSSL(domain:String, daemon:DaemonDB) async throws {
		let emailCommas = try daemon.getNotifyUsers().compactMap { $0.emailAddress }.joined(separator:",")
		try await Self.acquireSSL(domain:domain, email:emailCommas)
	}
	
	static func acquireSSL(domain:String, email:String) async throws {
		let acquireSSL = try await Command(bash:"sudo certbot certonly --webroot -w /var/www/html -n --agree-tos --no-eff-email -m \(email) -d \(domain)").runSync()
		guard acquireSSL.succeeded == true else {
			throw Error.unableToAcquireSSL(acquireSSL.stdout.compactMap({ String(data:$0, encoding:.utf8) }), acquireSSL.stderr.compactMap({ String(data:$0, encoding:.utf8) }))
		}
	}
	
	static func updateNotifyUsers(daemon:DaemonDB) async throws {
		let emailCommas = try daemon.getNotifyUsers().compactMap { $0.emailAddress }.joined(separator:",")
		let updateResult = try await Command(bash:"sudo certbot update_account --email \(emailCommas) --agree-tos --no-eff-email").runSync()
		guard updateResult.succeeded == true else {
			throw Error.unableToUpdateContacts
		}
	}
	
	static func removeSSL(domain:String) async throws {
		let removeAction = try await Command(bash:"sudo certbot delete -n -d \(domain)").runSync()
		guard removeAction.succeeded == true else {
			throw Error.unableToRemoveSSL
		}
	}
}
