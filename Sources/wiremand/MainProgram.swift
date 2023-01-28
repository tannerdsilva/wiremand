import Foundation
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
}
