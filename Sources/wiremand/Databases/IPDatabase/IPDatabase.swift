import AddressKit
import QuickLMDB
import Foundation
import Logging
import AsyncHTTPClient
import NIO
import System

class IPDatabase {
	enum ResolveStatus {
		case resolving
		case resolved(ResolvedIPInfo)
		case failedResolving(String)
	}
	enum Error:Swift.Error {
		case resolverLaunchError
		case pendingRemovalError
		case ipStackNotConfigured
	}
	internal static let eventLoop = MultiThreadedEventLoopGroup(numberOfThreads:2)
	fileprivate static func makeLogger() -> Logger {
		var newLogger = Logger(label:"ipdb")
		newLogger.logLevel = .debug
		return newLogger
	}
	internal static let logger = makeLogger()
	
	enum Databases:String {
		case metadata = "metadata"
		
		// any process that is currently "working" on resolving a pending IP
		case resolvingPID_pendingIP = "resolvingPID_pendingIP"	// [pid_t:String]
		case pendingIP_resolvingPID = "pendingIP_resolvingPID"	// [String:pid_t]
		
		// pending IP addresses that need resolving (and the corresponding date in which they were added to the database)
		case date_pendingIP = "date_pendingIP"	// [Date:String]
		case pendingIP_date = "pendingIP_date"	// [String:Date]
		
		// for IP addresses that are successfully resolved 
		case ipHash_resolvedData = "ipHash_resolvedData"				// [Data:ResolvedIPInfo]
		case ipHash_resolveSuccessDate = "ipHash_resolveSuccessDate"	// [Data:Date]
		case resolveSuccessDate_ipHash = "resolveSuccessDate_ipHash"	// [Date:Data]
		
		// for failed IP addresses
		case resolveFailDate_ipHash = "resolveFailDate_ipHash"			// [Date:Data]
		case ipHash_resolveFailDate = "ipHash_resolveFailDate"			// [Data:Date]
		case ipHash_resolveFailMessage = "ipHash_resolveFailMessage"	// [Data:String]
		
		// for both sucessful and failed IP addresses
		case ipHash_ipString = "ipHash_ipString"	// [Data:String]
	}    
	
	enum Metadatas:String {
		case ipstackAccessKey = "ipstack_accessKey"
	}
	
	static func produceIPHash(_ address:String) throws -> Data {
		var blakeHasher = Blake2bHasher(outputLength:24)
		let addressData = Data(address.utf8)
		try blakeHasher.update(data:addressData)
		return blakeHasher.export()
	}
	
	static func produceIPHash(_ address:AddressV4) throws -> Data {
		var blakeHasher = Blake2bHasher(outputLength:24)
		let addressData = Data(address.string.utf8)
		try blakeHasher.update(data:addressData)
		return blakeHasher.export()
	}
	
	static func produceIPHash(_ address:AddressV6) throws -> Data {
		var blakeHasher = Blake2bHasher(outputLength:24)
		let addressData = Data(address.string.utf8)
		try blakeHasher.update(data:addressData)
		return blakeHasher.export()
	}
	
	static func produceIDHash(_ identifier:String) throws -> Data {
		var blakeHasher = Blake2bHasher(outputLength:24)
		let addressData = Data(identifier.utf8)
		try blakeHasher.update(data:addressData)
		return blakeHasher.export()
	}
	
	let env:Environment
	
	// metadata
	let metadata:Database
	
	// for ip addresses that are currently being resolved
	let resolvingPID_pendingIP:Database
	let pendingIP_resolvingPID:Database
	
	// for ip addresses that need to be resolved
	let date_pendingIP:Database
	let pendingIP_date:Database
	
	// for successfully resolved data
	let ipHash_resolvedData:Database
	let ipHash_resolveSuccessDate:Database
	let resolveSuccessDate_ipHash:Database
	
	// for unsuccessfully resolved data
	let resolveFailDate_ipHash:Database
	let ipHash_resolveFailDate:Database
	let ipHash_resolveFailMessage:Database
	
	// for both success and failures
	let ipHash_ipString:Database

	// installs a pending address. does not mark the current pid as a resolver of this address
	fileprivate func installPending(ipv4:AddressV4, tx parentTrans:Transaction) throws {
		let makeDate = Date()
		try parentTrans.transact(readOnly:false) { someTrans in
			try self.date_pendingIP.setEntry(value:makeDate, forKey:ipv4, flags:[.noOverwrite], tx:someTrans)
			try self.pendingIP_date.setEntry(value:ipv4, forKey:makeDate, flags:[.noOverwrite], tx:someTrans)
			Self.logger.debug("pending IPv4 installed", metadata:["address": "\(ipv4.string)"])
		}
	}
	
	// installs a pending address. does not mark the current pid as a resolver for this address
	fileprivate func installPending(ipv6:AddressV6, tx parentTrans:Transaction) throws {
		let makeDate = Date()
		try parentTrans.transact(readOnly:false) { someTrans in
			try self.date_pendingIP.setEntry(value:makeDate, forKey:ipv6, flags:[.noOverwrite], tx:someTrans)
			try self.pendingIP_date.setEntry(value:ipv6, forKey:makeDate, flags:[.noOverwrite], tx:someTrans)
			Self.logger.debug("pending IPv6 installed", metadata:["address": "\(ipv6.string)"])
		}
	}
	
	// PRIVATE USE ONLY (for retrying failed addresses) installs a pending address. does not mark the current pid as a resolver of this address
	fileprivate func installPending(address:String, tx parentTrans:Transaction) throws {
		let makeDate = Date()
		try parentTrans.transact(readOnly:false) { someTrans in
			try self.date_pendingIP.setEntry(value:address, forKey:makeDate, flags:[.noOverwrite], tx:someTrans)
			try self.pendingIP_date.setEntry(value:makeDate, forKey:address, flags:[.noOverwrite], tx:someTrans)
			Self.logger.debug("pending IP (string) installed", metadata:["address": "\(address)"])
		}
	}
	
	// uninstalls a pending address string. will also delete any entry from the resolvers database if one exists.
	fileprivate func uninstallPending(addressString:String, tx parentTrans:Transaction) throws {
		try parentTrans.transact(readOnly:false) { someTrans in
			// delete data in date-pendingip databases
			let ipDateCursor = try self.pendingIP_date.cursor(tx:someTrans)
			let dateVal = try ipDateCursor.getEntry(.set, key:addressString).value
			let acquiredDate = Date(dateVal)!
			try self.date_pendingIP.deleteEntry(key:dateVal, tx:someTrans)
			try ipDateCursor.deleteEntry()
			
			// delete data in resolverpid-pendingip databases
			let myPID = getpid()
			let rPIDCursor = try self.pendingIP_resolvingPID.cursor(tx:someTrans)
			let resolverPID = pid_t(try rPIDCursor.getEntry(.set, key:addressString).value)!
			guard resolverPID == myPID else {
				Self.logger.error("unable to uninstall pending ID for a PID that is not our own")
				throw Error.pendingRemovalError
			}
			try self.resolvingPID_pendingIP.deleteEntry(key:myPID, tx:someTrans)
			try rPIDCursor.deleteEntry()

			Self.logger.debug("pending IP uninstalled", metadata:["db_address": "\(addressString)", "db_date": "\(acquiredDate)", "db_pid": "\(myPID)"])
		}
	}
	
	// returns the next pending address from the database
	fileprivate func getNextPendingAddress(tx parentTrans:Transaction) throws -> String {
		try parentTrans.transact(readOnly:false) { someTrans in
			let dateCursor = try date_pendingIP.cursor(tx:someTrans)
			let resolvingPIDCursor = try pendingIP_resolvingPID.cursor(tx:someTrans)
			let myPID = getpid()
			// find the first pending IP that does not have a PID that is resolving it
			for (_, curPendingIP) in dateCursor.makeIterator() {
				let curIPString = String(curPendingIP)!
				do {
					let resolverPID = pid_t(try resolvingPIDCursor.getEntry(.set, key:curPendingIP).value)!
					guard resolverPID != myPID else {
						throw LMDBError.keyExists
					}
					let checkPid = kill(resolverPID, 0)
					if checkPid != 0 {
						Self.logger.trace("dead resolver pid found.")
						try resolvingPID_pendingIP.setEntry(value:curPendingIP, forKey:myPID, flags:[.noOverwrite], tx:someTrans)
						try resolvingPIDCursor.setEntry(value:myPID, forKey:curPendingIP, flags:[.noOverwrite])
						Self.logger.debug("resolver pid assigned to pending ip address", metadata:["ip": "\(curIPString)"])
						return curIPString
					} else {
						Self.logger.trace("pid is actively resolving an ip address", metadata:["pid": "\(checkPid)", "ip": "\(curIPString)"])
					}
				} catch LMDBError.notFound {
					Self.logger.trace("no resolver pid found.")
					try resolvingPID_pendingIP.setEntry(value:curPendingIP, forKey:myPID, flags:[.noOverwrite], tx:someTrans)
					try resolvingPIDCursor.setEntry(value:myPID, forKey:curPendingIP, flags:[.noOverwrite])
					Self.logger.debug("resolver pid assigned to pending ip address", metadata:["ip": "\(curIPString)"])
					return curIPString
				}
			}
			throw LMDBError.notFound
		}
	}
	
	// installs a resolved address string into the database with the corresponding IP information.
	// may overwrite data if it already exists in the database
	fileprivate func installSuccessfulResolve(address:String, resolution:ResolvedIPInfo, tx parentTrans:Transaction) throws {
		let successDate = Date()
		let ipHash = try Self.produceIPHash(address)
		try parentTrans.transact(readOnly:false) { someTrans in
			// remove any "success dates" from this part of the database if it already exits. since this function needs to be able to overwrite existing data, we must take account of any previous success dates before we proceed to installing the new data
			do {
				let ipHashSuccessDate = try self.ipHash_resolveSuccessDate.getEntry(type:Date.self, forKey:ipHash, tx:someTrans)!
				try self.resolveSuccessDate_ipHash.deleteEntry(key:ipHashSuccessDate, tx:someTrans)
				try self.ipHash_resolveSuccessDate.deleteEntry(key:ipHash, tx:someTrans)
			} catch LMDBError.notFound {}
			
			try self.ipHash_resolvedData.setEntry(value:resolution, forKey:ipHash, tx:someTrans)
			try self.ipHash_resolveSuccessDate.setEntry(value:successDate, forKey:ipHash, tx:someTrans)
			try self.resolveSuccessDate_ipHash.setEntry(value:ipHash, forKey:successDate, tx:someTrans)
			try self.ipHash_ipString.setEntry(value:address, forKey:ipHash, tx:someTrans)
			Self.logger.debug("installed resolution info", metadata:["address": "\(address)"])
		}
	}
	
	// installs a failed resolution into the database with the corresponding error that caused the info to fail
	fileprivate func installFailedResolve(address:String, error:Swift.Error, tx parentTrans:Transaction) throws {
		let failDate = Date()
		let errorString = String(describing:error)
		let ipHash = try IPDatabase.produceIPHash(address)
		
		try parentTrans.transact(readOnly:false) { someTrans in
			try self.resolveFailDate_ipHash.setEntry(value:ipHash, forKey:failDate, tx:someTrans)
			try self.ipHash_resolveFailDate.setEntry(value:failDate, forKey:ipHash, tx:someTrans)
			try self.ipHash_resolveFailMessage.setEntry(value:errorString, forKey:ipHash, tx:someTrans)
			try self.ipHash_ipString.setEntry(value:address, forKey:ipHash, tx:someTrans)
			Self.logger.debug("installed resolution failure info", metadata:["address": "\(address)", "failMessage": "\(errorString)"])
		}
	}
	
	// removes a failed resolution from the database
	fileprivate func uninstallFailedResolve(addressString:String, tx parentTrans:Transaction) throws {
		let ipHash = try IPDatabase.produceIPHash(addressString)
		
		try parentTrans.transact(readOnly:false) { someTrans in
			let resolveFailDate = try self.ipHash_resolveFailDate.getEntry(type:Date.self, forKey:ipHash, tx:someTrans)!
			try self.resolveFailDate_ipHash.deleteEntry(key:resolveFailDate, tx:someTrans)
			try self.ipHash_resolveFailDate.deleteEntry(key:ipHash, tx:someTrans)
			try self.ipHash_resolveFailMessage.deleteEntry(key:ipHash, tx:someTrans)
			try self.ipHash_ipString.deleteEntry(key:ipHash, tx:someTrans)
		}
	}
	
	fileprivate func rotateStaleRecords(tx parentTrans:Transaction) throws {

		// failed records that are a month old will rotate back into the pending section of the databse (they will be removed as failed records before this happens)
		try parentTrans.transact(readOnly:false) { someTrans in
			let failedIPDateCursor = try self.resolveFailDate_ipHash.cursor(tx:someTrans)
			let hashStringCursor = try self.ipHash_ipString.cursor(tx:someTrans)
			let targetThreshold = Date().addingTimeInterval(-2629800)
			for (dateVal, hashVal) in failedIPDateCursor {
				let parseDate = Date(dateVal)!
				if (parseDate < targetThreshold) {
					// the date has crossd the threshold. remove it as a failed record and add it back as a pending address
					let addressString = String(try hashStringCursor.getEntry(.set, key:hashVal).value)!
					try self.uninstallFailedResolve(addressString:addressString, tx:someTrans)
					try self.installPending(address:addressString, tx:someTrans)
				} else {
					return
				}
			}
		}
		
		// succeeded record that are two months old will have a 1 in 5 chance of being rotated back into the database for re-resolution (addresses will not be removed from the "success" database while they are in the pending section of the database
		try parentTrans.transact(readOnly:false) { someTrans in
			let targetThreshold = Date().addingTimeInterval(-5259600)
			let succeededIPDateCursor = try self.resolveSuccessDate_ipHash.cursor(tx:someTrans)
			let hashStringCursor = try self.ipHash_ipString.cursor(tx:someTrans)
			for (dateVal, hashVal) in succeededIPDateCursor {
				let parseDate = Date(dateVal)!
				let randomVal = UInt8.random(in:0..<4)
				if (parseDate < targetThreshold) {
					let addressString = String(try hashStringCursor.getEntry(.set, key:hashVal).value)!
					Self.logger.trace("resolved ip has crossed the stale threshold.", metadata:["ip": "\(addressString)"])
					if (randomVal == 0) {
						Self.logger.trace("random number generator selected this record to re-resolve.", metadata:["ip":"\(addressString)"])
						do {
							try self.installPending(address:addressString, tx:someTrans)
						} catch LMDBError.keyExists {}
					} else {
						Self.logger.trace("random number generator did not select this record to re-resolve.", metadata:["ip":"\(addressString)"])
					}
				} else {
					return
				}
			}
		}
	}

	// launches a resolver for the current running PID
	fileprivate func launchResolver(tx parentTrans:Transaction) throws {
		// check if the access key is initialized before we launch a task
		let shouldReturn = try parentTrans.transact(readOnly:true) { someTrans -> Bool in
			let myPID = getpid();
			
			// verify that there is a valid API key in the database that we can use
			do {
				let _ = try self.metadata.getEntry(type:String.self, forKey:Metadatas.ipstackAccessKey.rawValue, tx:someTrans)
			} catch LMDBError.notFound {
				Self.logger.debug("resolver not launched - missing access key")
				throw LMDBError.notFound
			}
			
			// verify that this pid is not already resolving something
			guard try self.resolvingPID_pendingIP.containsEntry(key:myPID, tx:someTrans) == false else {
				Self.logger.debug("resolver not launched - this pid is already resolving an address.")
				throw LMDBError.keyExists
			}
			
			guard try self.pendingIP_date.getStatistics(tx:someTrans).entries > 0 else {
				Self.logger.debug("resolver not launched. there are no pending ip addresses.")
				return true
			}
			return false
		}
		if shouldReturn {
			return
		}
		
		// fly baby fly
		Task.detached {
			do {
				try await self.resolver_mainLoop()
			} catch let error {
				let myPID = getpid()
				Self.logger.error("resolver Task threw error", metadata:["pid": "\(myPID)", "error": "\(error)"])
				throw error
			}
		}
	}
	
	fileprivate func resolver_mainLoop() async throws {
		// define the basics
		let myPID = getpid()
		let client = HTTPClient(eventLoopGroupProvider:.shared(IPDatabase.eventLoop))
		defer {
			try? client.syncShutdown()
		}
		
		var currentAddress:String
		var accessKey:String
		do {
			// open a transaction and verify that our PID is not being used. if not, commit the PID to the database and begin resolving
			 (currentAddress, accessKey) = try env.transact(readOnly:false) { someTrans -> (String, String) in
				// verify again that the current PID is not taken in the database. then return the address string that is to be resolved
				guard try self.resolvingPID_pendingIP.containsEntry(key:myPID, tx:someTrans) == false else {
					throw LMDBError.keyExists
				}

				let getAccessKey = try self.metadata.getEntry(type:String.self, forKey:Metadatas.ipstackAccessKey.rawValue, tx:someTrans)!

				// assign our pid to the oldest pending ip address
				return (try self.getNextPendingAddress(tx:someTrans), getAccessKey)
			}
		} catch LMDBError.notFound {
			Self.logger.debug("resolver Task exiting. there are no pending IP addresses to resolve (or no access key configured).")
			return
		}
		
		var i = 0
		defer {
			if (i < 0) {
				try? env.sync()
			}
		}
		
		infiniteLoop: repeat {
			let resolvedIPInfo = try await ResolvedIPInfo.from(addressString:currentAddress, accessKey:accessKey, client:client)
			Self.logger.debug("successfully resolved IP address", metadata:["ip": "\(currentAddress)"])
			try self.env.transact(readOnly:false) { someTrans in
				try self.uninstallPending(addressString:currentAddress, tx:someTrans)
				try self.installSuccessfulResolve(address:currentAddress, resolution:resolvedIPInfo, tx:someTrans)
				do {
					accessKey = try self.metadata.getEntry(type:String.self, forKey:Metadatas.ipstackAccessKey.rawValue, tx:someTrans)!
					currentAddress = try getNextPendingAddress(tx:someTrans)
				} catch LMDBError.notFound {
					Self.logger.debug("resolver Task exiting. there are no more pending IP addresses to resolve.")
					return
				}
			}
			i += 1
		} while Task.isCancelled == false;
		Self.logger.debug("resolver Task was canceled by an external caller. exiting now...")
	}
	
	fileprivate func getResolveStatus(ipString:String, tx someTrans:Transaction) throws -> ResolveStatus {
		let ipHash = try Self.produceIPHash(ipString)
		do {
			let resolvedInfo = try self.ipHash_resolvedData.getEntry(type:ResolvedIPInfo.self, forKey:ipHash, tx:someTrans)!
			return .resolved(resolvedInfo)
		} catch LMDBError.notFound {
			do {
				let failMessage = try self.ipHash_resolveFailMessage.getEntry(type:String.self, forKey:ipHash, tx:someTrans)!
				return .failedResolving(failMessage)
			} catch LMDBError.notFound {
				if (try self.pendingIP_date.containsEntry(key:ipString, tx:someTrans) == true) {
					return .resolving
				} else {
					throw LMDBError.notFound
				}
			}
		}
	}
	
	init(base:URL, apiKey:String? = nil) throws {
		let makeEnvPath = base.appendingPathComponent("ip-db", isDirectory:true)
		
		let makeEnv = try Environment(path:makeEnvPath.path, flags:[.noSync], mapSize:4000000000, maxDBs:16, mode:[.ownerReadWriteExecute, .groupReadWriteExecute, .otherReadExecute])
		
		// determine what kind of access we have to the memorymap
		let accessVal = access(base.path, R_OK | W_OK | X_OK)
		if accessVal != 0 {
			Self.logger.error("access check error on database path", metadata:["exitCode": "\(accessVal)", "errno": "\(errno)", "path": "\(makeEnvPath.path)"])
		} else {
			Self.logger.info("access check for database passed")
		}
		let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
			let meta = try makeEnv.openDatabase(named:Databases.metadata.rawValue, tx:someTrans)
			
			if apiKey != nil {
				try meta.setEntry(value:apiKey!, forKey:Metadatas.ipstackAccessKey.rawValue, tx:someTrans)
			}
			
			let rPID_pIP = try makeEnv.openDatabase(named:Databases.resolvingPID_pendingIP.rawValue, tx:someTrans)
			let pIP_rPID = try makeEnv.openDatabase(named:Databases.pendingIP_resolvingPID.rawValue, tx:someTrans)
			
			let d_pIP = try makeEnv.openDatabase(named:Databases.date_pendingIP.rawValue, tx:someTrans)
			let pIP_d = try makeEnv.openDatabase(named:Databases.pendingIP_date.rawValue, tx:someTrans)
			
			let ipH_dat = try makeEnv.openDatabase(named:Databases.ipHash_resolvedData.rawValue, tx:someTrans)
			let ipH_date = try makeEnv.openDatabase(named:Databases.ipHash_resolveSuccessDate.rawValue, tx:someTrans)
			let date_ipH = try makeEnv.openDatabase(named:Databases.resolveSuccessDate_ipHash.rawValue, tx:someTrans)
			
			let resFD_ipH = try makeEnv.openDatabase(named:Databases.resolveFailDate_ipHash.rawValue, tx:someTrans)
			let ipH_resFD = try makeEnv.openDatabase(named:Databases.ipHash_resolveFailDate.rawValue, tx:someTrans)
			let ipH_resFM = try makeEnv.openDatabase(named:Databases.ipHash_resolveFailMessage.rawValue, tx:someTrans)
			
			let ipH_ipS = try makeEnv.openDatabase(named:Databases.ipHash_ipString.rawValue, tx:someTrans)
			
			return [meta, rPID_pIP, pIP_rPID, d_pIP, pIP_d, ipH_dat, ipH_date, date_ipH, resFD_ipH, ipH_resFD, ipH_resFM, ipH_ipS]
		}
		self.env = makeEnv
		self.metadata = dbs[0]
		self.resolvingPID_pendingIP = dbs[1]
		self.pendingIP_resolvingPID = dbs[2]
		self.date_pendingIP = dbs[3]
		self.pendingIP_date = dbs[4]
		self.ipHash_resolvedData = dbs[5]
		self.ipHash_resolveSuccessDate = dbs[6]
		self.resolveSuccessDate_ipHash = dbs[7]
		self.resolveFailDate_ipHash = dbs[8]
		self.ipHash_resolveFailDate = dbs[9]
		self.ipHash_resolveFailMessage = dbs[10]
		self.ipHash_ipString = dbs[11]
		
		Task.detached {
			try? makeEnv.transact(readOnly:false) { someTrans in
				try self.launchResolver(tx:someTrans)
			}
		}
	}
	
	func getResolveStatus(address:AddressV4) throws -> ResolveStatus {
		return try env.transact(readOnly:true) { someTrans in
			return try self.getResolveStatus(ipString:address.string, tx:someTrans)
		}
	}
	
	func getResolveStatus(address:AddressV6) throws -> ResolveStatus {
		return try env.transact(readOnly:true) { someTrans in
			return try self.getResolveStatus(ipString:address.string, tx:someTrans)
		}
	}
	
	func installAddress(ipv4:AddressV4) throws {
		let shouldSync = try env.transact(readOnly:false) { someTrans -> Bool in
			do {
				let resolveStatus = try self.getResolveStatus(ipString:ipv4.string, tx:someTrans)
				Self.logger.debug("installing an address that is already accounted for. no action taken.", metadata:["ip": "\(ipv4.string)", "status": "\(String(describing:resolveStatus))"])
				return false
			} catch LMDBError.notFound {
				Self.logger.debug("installing address in database", metadata:["ip": "\(ipv4.string)"])
				try self.installPending(address:ipv4.string, tx:someTrans)
				try self.rotateStaleRecords(tx:someTrans)
				try? self.launchResolver(tx:someTrans)
				return true
			}
		}
		if (shouldSync) {
			try env.sync()
		}
	}
	
	func installAddress(ipv6:AddressV6) throws {
		let shouldSync = try env.transact(readOnly:false) { someTrans -> Bool in
			do {
				let resolveStatus = try self.getResolveStatus(ipString:ipv6.string, tx:someTrans)
				Self.logger.debug("installing an address that is alrady accounted for. no action taken.", metadata:["ip": "\(ipv6.string)", "status": "\(String(describing:resolveStatus))"])
				return false
			} catch LMDBError.notFound {
				Self.logger.debug("installing address in database", metadata:["ip": "\(ipv6.string)"])
				try self.installPending(address:ipv6.string, tx:someTrans)
				try self.rotateStaleRecords(tx:someTrans)
				try? self.launchResolver(tx:someTrans)
				return true
			}
		}
		if (shouldSync) {
			try env.sync()
		}
	}
}
