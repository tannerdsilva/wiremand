import Foundation
import SwiftSlash

struct CertbotExecute {
    enum Error:Swift.Error {
        case unableToAcquireSSL([String], [String])
    }
	static func acquireSSL(domain:String, email:String = "tsilva@escalantegolf.com") async throws {
        let acquireSSL = try await Command(bash:"sudo certbot certonly --webroot -w /var/www/html -n --agree-tos -m \(email) -d \(domain)").runSync()
        guard acquireSSL.succeeded == true else {
            throw Error.unableToAcquireSSL(acquireSSL.stdout.compactMap({ String(data:$0, encoding:.utf8) }), acquireSSL.stderr.compactMap({ String(data:$0, encoding:.utf8) }))
        }
    }
}
